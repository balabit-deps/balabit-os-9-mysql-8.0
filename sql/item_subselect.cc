/* Copyright (c) 2002, 2025, Oracle and/or its affiliates.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License, version 2.0,
   as published by the Free Software Foundation.

   This program is designed to work with certain software (including
   but not limited to OpenSSL) that is licensed under separate terms,
   as designated in a particular file or component or in included license
   documentation.  The authors of MySQL hereby grant you an additional
   permission to link the program and your derivative works with the
   separately licensed software that they have either included with
   the program or referenced in the documentation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License, version 2.0, for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

/**
  @file

  @brief
  Implements the subselect Item, used when there is a subselect in a
  SELECT list, WHERE, etc.
*/

#include "sql/item_subselect.h"

#include <climits>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <string>
#include <utility>

#include "decimal.h"
#include "lex_string.h"
#include "m_ctype.h"
#include "m_string.h"
#include "my_alloc.h"
#include "my_base.h"
#include "my_compiler.h"
#include "my_dbug.h"
#include "my_pointer_arithmetic.h"
#include "my_sys.h"
#include "mysql_com.h"
#include "mysqld_error.h"
#include "scope_guard.h"
#include "sql/check_stack.h"
#include "sql/current_thd.h"  // current_thd
#include "sql/debug_sync.h"   // DEBUG_SYNC
#include "sql/derror.h"       // ER_THD
#include "sql/field.h"
#include "sql/handler.h"
#include "sql/item_cmpfunc.h"
#include "sql/item_func.h"
#include "sql/item_sum.h"                       // Item_sum_max
#include "sql/iterators/basic_row_iterators.h"  // ZeroRowsIterator
#include "sql/iterators/composite_iterators.h"  // FilterIterator
#include "sql/iterators/ref_row_iterators.h"
#include "sql/iterators/row_iterator.h"  // RowIterator
#include "sql/iterators/timing_iterator.h"
#include "sql/join_optimizer/access_path.h"
#include "sql/join_optimizer/cost_model.h"
#include "sql/join_optimizer/join_optimizer.h"
#include "sql/key.h"
#include "sql/my_decimal.h"
#include "sql/mysqld.h"  // in_left_expr_name
#include "sql/opt_explain_format.h"
#include "sql/opt_trace.h"  // OPT_TRACE_TRANSFORM
#include "sql/opt_trace_context.h"
#include "sql/parse_tree_nodes.h"  // PT_subquery
#include "sql/query_options.h"
#include "sql/query_result.h"
#include "sql/sql_class.h"  // THD
#include "sql/sql_const.h"
#include "sql/sql_error.h"
#include "sql/sql_executor.h"
#include "sql/sql_lex.h"  // Query_block
#include "sql/sql_list.h"
#include "sql/sql_opt_exec_shared.h"
#include "sql/sql_optimizer.h"  // JOIN
#include "sql/sql_select.h"
#include "sql/sql_test.h"       // print_where
#include "sql/sql_tmp_table.h"  // free_tmp_table
#include "sql/sql_union.h"      // Query_result_union
#include "sql/system_variables.h"
#include "sql/table.h"
#include "sql/temp_table_param.h"
#include "sql/thd_raii.h"
#include "sql/window.h"
#include "sql_string.h"
#include "template_utils.h"

class Json_wrapper;

Item_subselect::Item_subselect()
    : Item_result_field(),
      value_assigned(false),
      traced_before(false),
      substitution(nullptr),
      in_cond_of_tab(NO_PLAN_IDX),
      used_tables_cache(0),
      have_to_be_excluded(false),
      changed(false) {
  set_subquery();
  reset();
  /*
    Item value is NULL if Query_result_interceptor didn't change this value
    (i.e. some rows will be found returned)
  */
  null_value = true;
}

Item_subselect::Item_subselect(const POS &pos)
    : super(pos),
      value_assigned(false),
      traced_before(false),
      substitution(nullptr),
      in_cond_of_tab(NO_PLAN_IDX),
      used_tables_cache(0),
      have_to_be_excluded(false),
      changed(false) {
  set_subquery();
  reset();
  /*
    Item value is NULL if Query_result_interceptor didn't change this value
    (i.e. some rows will be found returned)
  */
  null_value = true;
}

void Item_subselect::init(Query_block *query_block,
                          Query_result_subquery *result) {
  /*
    Please see Item_singlerow_subselect::invalidate_and_restore_query_block(),
    which depends on alterations to the parse tree implemented here.
  */

  DBUG_TRACE;
  DBUG_PRINT("enter", ("query_block: %p", query_block));
  unit = query_block->master_query_expression();

  if (unit->item) {
    subquery = std::move(unit->item->subquery);
    parsing_place = unit->item->parsing_place;
    unit->item = this;
    subquery->change_query_result(current_thd, this, result);
  } else {
    Query_block *outer_query_block = unit->outer_query_block();
    /*
      do not take into account expression inside aggregate functions because
      they can access original table fields
    */
    parsing_place =
        (outer_query_block->in_sum_expr ? CTX_NONE
                                        : outer_query_block->parsing_place);
    subquery.reset(new (*THR_MALLOC) SubqueryWithResult(unit, result, this));
  }
  {
    Query_block *upper = unit->outer_query_block();
    if (upper->parsing_place == CTX_HAVING) upper->subquery_in_having = true;
  }
}

/**
  Accumulate missing used_tables information from embedded query expression
  into the subquery.
  This function relies on a few other functions to accumulate information:
    accumulate_expression(), accumulate_condition().

  Currently, the only property that is accumulated is INNER_TABLE_BIT.
  Information about local tables and outer references are accumulated in
  mark_as_dependent() (@see item.cc).
  RAND_TABLE_BIT is currently not accumulated (but uncacheable is used instead).

  @todo - maybe_null is not set properly for all types of subqueries and
          expressions. Use this sketch as a guideline for further handling:

  - When constructing an Item_subselect, maybe_null is false and null_value
    is true. This is obviously wrong.

  - When constructing an Item_in_subselect (subclass of Item_subselect),
    maybe_null is set true and null_value is set false.

  We should probably keep both maybe_null and null_value as false in
  the constructor. Then, set maybe_null during preparation, according to
  type of subquery:

  - Scalar subquery is nullable when query block may have an empty result (not
    DUAL or implicitly grouped).

  - Scalar subquery is nullable when one of the selected expressions
    are nullable.

  - Scalar subquery is nullable when WHERE clause or HAVING clause is non-empty
    and not always true.

  - EXISTS subquery is never nullable!

  - IN subquery nullability ignores subquery cardinality.

  - IN subquery is nullable when one of the selected expressions are nullable.

  - UNIONed query blocks may cancel out nullability.

*/
void Item_subselect::accumulate_properties() {
  for (Query_block *select = unit->first_query_block(); select != nullptr;
       select = select->next_query_block())
    accumulate_properties(select);

  for (auto qt : unit->query_terms<QTC_POST_ORDER, VL_SKIP_LEAVES>()) {
    /*
      qt->query_block() may only contain components with special table
      dependencies in the ORDER BY clause, so inspect these expressions only.
      (The SELECT list may contain table references that are valid only in
       a local scope - references to the UNION temporary table - and should
       not be propagated to the subquery level.)
    */
    for (ORDER *order = qt->query_block()->order_list.first; order != nullptr;
         order = order->next)
      accumulate_condition(*order->item);
  }
  // Save used tables information for the subquery only
  used_tables_cache |= m_subquery_used_tables;
}

/**
  Accumulate missing used_tables information for a query block.

  @param select Reference to query block
*/
void Item_subselect::accumulate_properties(Query_block *select) {
  for (Item *item : select->visible_fields()) {
    accumulate_expression(item);
  }

  if (select->where_cond()) accumulate_condition(select->where_cond());

  if (select->m_current_table_nest)
    walk_join_list(*select->m_current_table_nest,
                   [this](Table_ref *tr) -> bool {
                     if (tr->join_cond()) accumulate_condition(tr->join_cond());
                     return false;
                   });

  for (ORDER *group = select->group_list.first; group; group = group->next)
    accumulate_condition(*group->item);

  if (select->having_cond()) accumulate_condition(select->having_cond());

  for (ORDER *order = select->order_list.first; order; order = order->next)
    accumulate_expression(*order->item);
  if (select->has_tables()) m_subquery_used_tables |= INNER_TABLE_BIT;

  List_iterator<Window> wi(select->m_windows);
  Window *w;
  while ((w = wi++)) {
    for (ORDER *wp = w->first_partition_by(); wp != nullptr; wp = wp->next)
      accumulate_expression(*wp->item);
    for (ORDER *wo = w->first_order_by(); wo != nullptr; wo = wo->next)
      accumulate_expression(*wo->item);
  }
}

/**
  Accumulate used_tables information for an expression from a query block.

  @param item  Reference to expression.
*/
void Item_subselect::accumulate_expression(Item *item) {
  if (item->used_tables() & ~OUTER_REF_TABLE_BIT)
    m_subquery_used_tables |= INNER_TABLE_BIT;
  set_nullable(is_nullable() || item->is_nullable());
}

/**
  Accumulate used_tables information for a condition from a query block.

  @param item  Reference to condition.
*/
void Item_subselect::accumulate_condition(Item *item) {
  if (item->used_tables() & ~OUTER_REF_TABLE_BIT)
    m_subquery_used_tables |= INNER_TABLE_BIT;
}

void Item_subselect::create_iterators(THD *thd) {
  if (indexsubquery_engine != nullptr) {
    indexsubquery_engine->create_iterators(thd);
  }
}

Item_subselect::enum_engine_type Item_subselect::engine_type() const {
  if (indexsubquery_engine != nullptr) {
    switch (indexsubquery_engine->engine_type()) {
      case subselect_indexsubquery_engine::INDEXSUBQUERY_ENGINE:
        return Item_subselect::INDEXSUBQUERY_ENGINE;
      case subselect_indexsubquery_engine::HASH_SJ_ENGINE:
        return Item_subselect::HASH_SJ_ENGINE;
      default:
        assert(false);
    }
  }
  return Item_subselect::OTHER_ENGINE;
}

const TABLE *Item_subselect::get_table() const {
  return down_cast<subselect_hash_sj_engine *>(indexsubquery_engine)
      ->get_table();
}

const Index_lookup &Item_subselect::index_lookup() const {
  return down_cast<subselect_hash_sj_engine *>(indexsubquery_engine)
      ->index_lookup();
}

join_type Item_subselect::get_join_type() const {
  return down_cast<subselect_hash_sj_engine *>(indexsubquery_engine)
      ->get_join_type();
}

void Item_subselect::cleanup() {
  Item_result_field::cleanup();
  if (indexsubquery_engine) {
    indexsubquery_engine->cleanup();
    destroy(indexsubquery_engine);
    indexsubquery_engine = nullptr;
  }
  if (subquery) subquery->cleanup();
  reset();
  value_assigned = false;
  traced_before = false;
  in_cond_of_tab = NO_PLAN_IDX;
}

void Item_singlerow_subselect::cleanup() {
  DBUG_TRACE;
  Item_subselect::cleanup();
}

/**
  Decide whether to mark the injected left expression "outer" relative to
  the subquery. It should be marked as outer in the following cases:

  1) If the left expression is not constant.

  2) If the left expression could be a constant NULL and we care about the
  difference between UNKNOWN and FALSE. In this case, JOIN::optimize() for
  the subquery must be prevented from evaluating any triggered condition, as
  the triggers for such conditions have not yet been properly set by
  Item_in_optimizer::val_int(). By marking the left expression as outer, a
  triggered condition using it will not be considered constant, will not be
  evaluated by JOIN::optimize(); it will only be evaluated by JOIN::exec()
  which is called from Item_in_optimizer::val_int()

  3) If the left expression comes from a subquery and is not a basic
  constant. In this case, the value cannot be read until after the subquery
  has been evaluated. By marking it as outer, we prevent it from being read
  when JOIN::optimize() attempts to evaluate constant conditions.

  @param[in] left_row The item that represents the left operand of the IN
                      operator

  @param[in] col      The column number of the expression in the left operand
                      to possibly mark as dependent of the outer select

  @returns true if we should mark the injected left expression "outer"
                relative to the subquery
*/
bool Item_in_subselect::mark_as_outer(Item *left_row, size_t col) {
  const Item *left_col = left_row->element_index(col);
  return !left_col->const_item() ||
         (!abort_on_null && left_col->is_nullable()) ||
         (left_row->type() == SUBSELECT_ITEM && !left_col->basic_const_item());
}

bool Item_in_subselect::finalize_exists_transform(THD *thd,
                                                  Query_block *query_block) {
  assert(strategy == Subquery_strategy::CANDIDATE_FOR_IN2EXISTS_OR_MAT ||
         strategy == Subquery_strategy::SUBQ_EXISTS);
  /*
    Note that if the subquery is "SELECT1 UNION SELECT2" then this is not
    working optimally (Bug#14215895).
  */
  if (!(unit->global_parameters()->select_limit = new Item_int(1))) return true;
  unit->global_parameters()->m_internal_limit = true;

  if (unit->set_limit(thd, unit->global_parameters()))
    return true; /* purecov: inspected */

  if (unit->finalize(thd)) {
    return true;
  }

  query_block->join->allow_outer_refs = true;  // for JOIN::set_prefix_tables()
  strategy = Subquery_strategy::SUBQ_EXISTS;
  return false;
}

Item *remove_in2exists_conds(Item *conds) {
  bool modified = false;
  List<Item> new_conds;
  if (WalkConjunction(conds, [&modified, &new_conds](Item *cond) {
        if (cond->created_by_in2exists()) {
          modified = true;
          return false;
        } else {
          return new_conds.push_back(cond);
        }
      })) {
    return nullptr;
  }
  return modified ? CreateConjunction(&new_conds) : conds;
}

bool Item_in_subselect::finalize_materialization_transform(THD *thd,
                                                           JOIN *join) {
  assert(strategy == Subquery_strategy::CANDIDATE_FOR_IN2EXISTS_OR_MAT);

  assert(join == subquery->single_query_block()->join);
  // No UNION in materialized subquery so this holds:
  assert(join->query_block == unit->first_query_block());
  assert(join->query_expression() == unit);
  assert(unit->global_parameters()->select_limit == nullptr);

  strategy = Subquery_strategy::SUBQ_MATERIALIZATION;

  // We need to undo several changes which IN->EXISTS had done:

  /*
    The conditions added by in2exists depend on the concrete value from the
    outer query block, so they need to be removed before we materialize.
  */

  // This part is not relevant for the hypergraph optimizer.
  if (join->where_cond)
    join->where_cond = remove_in2exists_conds(join->where_cond);
  if (join->having_cond)
    join->having_cond = remove_in2exists_conds(join->having_cond);

  // This part is only relevant for the hypergraph optimizer.
  unit->change_to_access_path_without_in2exists(thd);
  assert(!in2exists_info->dependent_before);
  if (unit->finalize(thd)) {
    return true;
  }

  join->query_block->uncacheable &= ~UNCACHEABLE_DEPENDENT;
  unit->uncacheable &= ~UNCACHEABLE_DEPENDENT;

  OPT_TRACE_TRANSFORM(&thd->opt_trace, oto0, oto1,
                      subquery->single_query_block()->select_number,
                      "IN (SELECT)", "materialization");
  oto1.add("chosen", true);

  subselect_hash_sj_engine *const new_engine =
      new (thd->mem_root) subselect_hash_sj_engine(this, unit);
  if (!new_engine) return true;
  if (new_engine->setup(thd, *unit->get_unit_column_types())) {
    /*
      For some reason we cannot use materialization for this IN predicate.
      Delete all materialization-related objects, and return error.
    */
    new_engine->cleanup();
    destroy(new_engine);
    return true;
  }
  indexsubquery_engine = new_engine;

  join->allow_outer_refs = false;  // for JOIN::set_prefix_tables()
  return false;
}

void Item_in_subselect::cleanup() {
  DBUG_TRACE;
  if (left_expr_cache) {
    left_expr_cache->destroy_elements();
    destroy(left_expr_cache);
    left_expr_cache = nullptr;
  }
  left_expr_cache_filled = false;
  need_expr_cache = true;

  switch (strategy) {
    case Subquery_strategy::SUBQ_MATERIALIZATION:
      if (in2exists_info->dependent_after) {
        unit->first_query_block()->uncacheable |= UNCACHEABLE_DEPENDENT;
        unit->uncacheable |= UNCACHEABLE_DEPENDENT;
      }
      [[fallthrough]];
    case Subquery_strategy::SUBQ_EXISTS:
      /*
        Back to EXISTS_OR_MAT, so that next execution of this statement can
        choose between the two.
      */
      unit->global_parameters()->select_limit = nullptr;
      strategy = Subquery_strategy::CANDIDATE_FOR_IN2EXISTS_OR_MAT;
      break;
    default:
      break;
  }

  Item_subselect::cleanup();
}

AccessPath *Item_in_subselect::root_access_path() const {
  if (strategy == Subquery_strategy::SUBQ_MATERIALIZATION &&
      indexsubquery_engine->engine_type() ==
          subselect_indexsubquery_engine::HASH_SJ_ENGINE) {
    return down_cast<subselect_hash_sj_engine *>(indexsubquery_engine)
        ->root_access_path();
  } else {
    // Only subselect_hash_sj_engine owns its own iterator;
    // for subselect_indexsubquery_engine, the unit still has it, since it's a
    // normally executed query block. Thus, we should never get called
    // otherwise.
    //
    // However, in some situations where the hypergraph optimizer prints out
    // the query to the log for debugging, it isn't fully optimized
    // yet and might not yet have an iterator. Thus, return nullptr instead of
    // assert-failing.
    assert(current_thd->lex->using_hypergraph_optimizer());
    return nullptr;
  }
}

bool Item_subselect::fix_fields(THD *thd, Item **ref) {
  char const *save_where = thd->where;
  uint8 uncacheable;
  bool res;

  assert(!fixed);
  assert(indexsubquery_engine == nullptr);

#ifndef NDEBUG
  // Engine accesses THD via its 'item' pointer, check it:
  assert(subquery->get_item() == this);
#endif

  if (check_stack_overrun(thd, STACK_MIN_SIZE, (uchar *)&res)) return true;

  if (!(res = subquery->prepare(thd))) {
    // all transformation is done (used by prepared statements)
    changed = true;

    // Accumulate properties referring to "inner tables"
    accumulate_properties();

    /*
      Substitute the current item with an Item_in_optimizer that was
      created by Item_in_subselect::select_in_like_transformer and
      call fix_fields for the substituted item which in turn calls
      subquery->prepare for the subquery predicate.
    */
    if (substitution) {
      int ret = 0;
      (*ref) = substitution;
      if (item_name.is_set()) {
        substitution->item_name = item_name;
      }
      if (have_to_be_excluded) {
        unit->exclude_level();
      }
      substitution = nullptr;
      thd->where = "checking transformed subquery";
      if (!(*ref)->fixed) ret = (*ref)->fix_fields(thd, ref);
      thd->where = save_where;
      return ret;
    }
    // Is it one field subselect?
    if (unit_cols() > max_columns) {
      my_error(ER_OPERAND_COLUMNS, MYF(0), 1);
      return true;
    }
    if (resolve_type(thd)) goto err;
  } else
    goto err;

  if ((uncacheable = unit->uncacheable)) {
    if (uncacheable & UNCACHEABLE_RAND) {
      m_subquery_used_tables |= RAND_TABLE_BIT;
      used_tables_cache |= RAND_TABLE_BIT;
    }
  }

  /*
    If this subquery references window functions, per the SQL standard they
    are aggregated in the subquery's query block, and never outside of it, so:
  */
  assert(!has_wf());

  fixed = true;

err:
  thd->where = save_where;
  return res;
}

bool Item_subselect::walk(Item_processor processor, enum_walk walk,
                          uchar *arg) {
  if ((walk & enum_walk::PREFIX) && (this->*processor)(arg)) return true;

  if ((walk & enum_walk::SUBQUERY) && unit->walk(processor, walk, arg))
    return true;

  return (walk & enum_walk::POSTFIX) && (this->*processor)(arg);
}

/**
  Register subquery to the table where it is used within a condition.

  @param arg    qep_row to which the subquery belongs

  @retval false

  @note We always return "false" as far as we don't want to dive deeper because
        we explain inner subqueries in their joins contexts.
*/

bool Item_subselect::explain_subquery_checker(uchar **arg) {
  qep_row *qr = reinterpret_cast<qep_row *>(*arg);

  qr->register_where_subquery(unit);
  return false;
}

bool Item_subselect::exec(THD *thd) {
  DBUG_TRACE;
  /*
    Do not execute subselect in case of a fatal error
    or if the query has been killed.
  */
  if (thd->is_error() || thd->killed) return true;

  // No subqueries should be evaluated when analysing a view
  assert(!thd->lex->is_view_context_analysis());
  /*
    Simulate a failure in sub-query execution. Used to test e.g.
    out of memory or query being killed conditions.
  */
  DBUG_EXECUTE_IF("subselect_exec_fail", return true;);

  /*
    Disable tracing of subquery execution if
    1) this is not the first time the subselect is executed, and
    2) REPEATED_SUBSELECT is disabled
  */
  Opt_trace_context *const trace = &thd->opt_trace;
  const bool disable_trace =
      traced_before &&
      !trace->feature_enabled(Opt_trace_context::REPEATED_SUBSELECT);
  Opt_trace_disable_I_S disable_trace_wrapper(trace, disable_trace);
  traced_before = true;

  Opt_trace_object trace_wrapper(trace);
  Opt_trace_object trace_exec(trace, "subselect_execution");
  trace_exec.add_select_number(unit->first_query_block()->select_number);
  Opt_trace_array trace_steps(trace, "steps");

  // subselect_hash_sj_engine creates its own iterators; it does not call
  // exec().
  bool should_create_iterators =
      !(indexsubquery_engine != nullptr &&
        indexsubquery_engine->engine_type() ==
            subselect_indexsubquery_engine::HASH_SJ_ENGINE);

  // Normally, the unit would be optimized here, but statements like DO and SET
  // may still rely on lazy optimization. Also, we might not have iterators,
  // so make sure to create them if they're missing.
  if (!unit->is_optimized()) {
    if (unit->optimize(thd, /*materialize_destination=*/nullptr,
                       /*create_iterators=*/false,
                       /*finalize_access_paths=*/false))
      return true;

    // NOTE: We defer finalization and creating iterators to the statements
    // below; asking optimize() to finalize a plan with two choices
    // (materialization and exists) rightfully causes a failed assertion. We
    // should probably have made a cost-based choice between the two here, but
    // as it stands, we will always implicitly choose in2exists in these cases
    // (DO/SET).
  }
  if (should_create_iterators && unit->root_access_path() != nullptr) {
    if (unit->finalize(thd)) {
      return true;
    }
    if (unit->force_create_iterators(thd)) return true;
  }
  if (indexsubquery_engine != nullptr) {
    return indexsubquery_engine->exec(thd);
  } else {
    return subquery->exec(thd);
  }
}

/// @see Query_expression::fix_after_pullout()
void Item_subselect::fix_after_pullout(Query_block *parent_query_block,
                                       Query_block *removed_query_block)

{
  /* Clear usage information for this subquery predicate object */
  used_tables_cache = 0;
  m_subquery_used_tables = 0;

  unit->fix_after_pullout(parent_query_block, removed_query_block);

  // Accumulate properties like INNER_TABLE_BIT
  accumulate_properties();

  if (unit->uncacheable & UNCACHEABLE_RAND) {
    m_subquery_used_tables |= RAND_TABLE_BIT;
  }

  used_tables_cache = m_subquery_used_tables;
}

bool Item_in_subselect::walk(Item_processor processor, enum_walk walk,
                             uchar *arg) {
  if (left_expr->walk(processor, walk, arg)) return true;
  return Item_subselect::walk(processor, walk, arg);
}

Item *Item_in_subselect::transform(Item_transformer transformer, uchar *arg) {
  left_expr = left_expr->transform(transformer, arg);
  if (left_expr == nullptr) return nullptr;

  return (this->*transformer)(arg);
}

Item *Item_in_subselect::compile(Item_analyzer analyzer, uchar **arg_p,
                                 Item_transformer transformer, uchar *arg_t) {
  if (!(this->*analyzer)(arg_p)) return this;

  // Compile the left expression of the IN subquery
  Item *item = left_expr->compile(analyzer, arg_p, transformer, arg_t);
  if (item == nullptr) return nullptr; /* purecov: inspected */
  if (item != left_expr) current_thd->change_item_tree(&left_expr, item);

  return (this->*transformer)(arg_t);
}

/*
  Compute the IN predicate if the left operand's cache changed.
*/

bool Item_in_subselect::exec(THD *thd) {
  DBUG_TRACE;
  assert(strategy != Subquery_strategy::SUBQ_MATERIALIZATION ||
         indexsubquery_engine->engine_type() ==
             subselect_indexsubquery_engine::HASH_SJ_ENGINE);
  /*
    Initialize the cache of the left predicate operand. This has to be done as
    late as now, because Cached_item directly contains a resolved field (not
    an item, and in some cases (when temp tables are created), these fields
    end up pointing to the wrong field. One solution is to change Cached_item
    to not resolve its field upon creation, but to resolve it dynamically
    from a given Item_ref object.
    Do not init the cache if a previous execution decided that it is not needed.
    TODO: the cache should be applied conditionally based on:
    - rules - e.g. only if the left operand is known to be ordered, and/or
    - on a cost-based basis, that takes into account the cost of a cache
      lookup, the cache hit rate, and the savings per cache hit.
  */
  if (need_expr_cache && !left_expr_cache &&
      strategy == Subquery_strategy::SUBQ_MATERIALIZATION &&
      init_left_expr_cache(thd))
    return true;

  if (left_expr_cache != nullptr) {
    const int result = update_item_cache_if_changed(*left_expr_cache);
    if (left_expr_cache_filled &&  // cache was previously filled
        result < 0)  // new value is identical to previous cached value
    {
      /*
        We needn't do a full execution, can just reuse "value", "was_null",
        "null_value" of the previous execution.
      */
      return false;
    }
    left_expr_cache_filled = true;
  }

  const bool uncacheable = unit->uncacheable || indexsubquery_engine != nullptr;
  if (unit->is_executed() && uncacheable) {
    // Second or later execution (and it's actually going to be executed,
    // not just the return the cached value from the first run), so clear out
    // state from the previous run(s).
    //
    // Note that subselect_hash_sj_engine and subselect_indexsubquery_engine
    // are both uncacheable (due to dependency on the left side), even if the
    // underlying unit is not marked as such.
    null_value = false;
    was_null = false;
  }
  return Item_subselect::exec(thd);
}

Item::Type Item_subselect::type() const { return SUBSELECT_ITEM; }

bool Item_subselect::resolve_type(THD *) {
  subquery->fix_length_and_dec(nullptr);
  return false;
}

Item *Item_subselect::get_tmp_table_item(THD *thd_arg) {
  DBUG_TRACE;
  if (!has_aggregation() && !(const_for_execution() &&
                              evaluate_during_optimization(
                                  this, thd_arg->lex->current_query_block()))) {
    Item *result = new Item_field(result_field);
    return result;
  }
  Item *result = copy_or_same(thd_arg);
  return result;
}

void Item_subselect::update_used_tables() {
  if (!unit->uncacheable) {
    // There is no expression with outer reference, randomness or side-effect,
    // so the subquery's content depends only on its inner tables:
    m_subquery_used_tables &= INNER_TABLE_BIT;
  }
  used_tables_cache = m_subquery_used_tables;
}

void Item_subselect::print(const THD *thd, String *str,
                           enum_query_type query_type) const {
  if (subquery) {
    str->append('(');
    if (query_type & QT_SUBSELECT_AS_ONLY_SELECT_NUMBER) {
      str->append("select #");
      uint select_number = unit->first_query_block()->select_number;
      str->append_ulonglong(select_number);
    } else if (indexsubquery_engine != nullptr) {
      indexsubquery_engine->print(thd, str, query_type);
    } else {
      subquery->print(thd, str, query_type);
    }
    str->append(')');
  } else
    str->append("(...)");
}

/* Single value subselect interface class */
class Query_result_scalar_subquery : public Query_result_subquery {
 public:
  explicit Query_result_scalar_subquery(Item_subselect *item_arg)
      : Query_result_subquery(item_arg) {}
  bool send_data(THD *thd, const mem_root_deque<Item *> &items) override;
};

bool Query_result_scalar_subquery::send_data(
    THD *thd, const mem_root_deque<Item *> &items) {
  DBUG_TRACE;
  Item_singlerow_subselect *it = down_cast<Item_singlerow_subselect *>(item);
  if (it->assigned()) {
    my_error(ER_SUBQUERY_NO_1_ROW, MYF(0));
    return true;
  }
  uint i = 0;
  for (Item *val_item : VisibleFields(items)) {
    it->store(i++, val_item);
  }
  if (thd->is_error()) return true;

  it->assigned(true);
  return false;
}

Item_singlerow_subselect::Item_singlerow_subselect(Query_block *query_block)
    : Item_subselect(), value(nullptr), no_rows(false) {
  DBUG_TRACE;
  init(query_block, new (*THR_MALLOC) Query_result_scalar_subquery(this));
  set_nullable(true);  // if the subquery is empty, value is NULL
  max_columns = UINT_MAX;
}

Query_block *Item_singlerow_subselect::invalidate_and_restore_query_block() {
  DBUG_TRACE;
  Query_block *result = unit->first_query_block();

  assert(result);

  /*
    This code restore the parse tree in it's state before the execution of
    Item_singlerow_subselect::Item_singlerow_subselect(),
    and in particular decouples this object from the Query_block,
    so that the Query_block can be used with a different flavor
    or Item_subselect instead, as part of query rewriting.
  */
  unit->item = nullptr;

  return result;
}

/* used in independent ALL/ANY optimisation */
class Query_result_max_min_subquery final : public Query_result_subquery {
  Item_cache *cache;
  bool (Query_result_max_min_subquery::*op)();
  bool fmax;
  /**
    If ignoring NULLs, comparisons will skip NULL values. If not
    ignoring NULLs, the first (if any) NULL value discovered will be
    returned as the maximum/minimum value.
  */
  bool ignore_nulls;

 public:
  Query_result_max_min_subquery(Item_subselect *item_arg, bool mx,
                                bool ignore_nulls)
      : Query_result_subquery(item_arg),
        cache(nullptr),
        fmax(mx),
        ignore_nulls(ignore_nulls) {}
  void cleanup() override;
  bool send_data(THD *thd, const mem_root_deque<Item *> &items) override;

 private:
  bool cmp_real();
  bool cmp_int();
  bool cmp_decimal();
  bool cmp_str();
};

void Query_result_max_min_subquery::cleanup() {
  DBUG_TRACE;
  cache = nullptr;
}

bool Query_result_max_min_subquery::send_data(
    THD *, const mem_root_deque<Item *> &items) {
  DBUG_TRACE;
  Item_maxmin_subselect *it = (Item_maxmin_subselect *)item;
  Item *val_item = nullptr;
  for (Item *item : VisibleFields(items)) {
    val_item = item;
    break;
  }
  it->register_value();
  if (it->assigned()) {
    cache->store(val_item);
    if ((this->*op)()) it->store(0, cache);
  } else {
    if (!cache) {
      cache = Item_cache::get_cache(val_item);
      switch (val_item->result_type()) {
        case REAL_RESULT:
          op = &Query_result_max_min_subquery::cmp_real;
          break;
        case INT_RESULT:
          op = &Query_result_max_min_subquery::cmp_int;
          break;
        case STRING_RESULT:
          op = &Query_result_max_min_subquery::cmp_str;
          break;
        case DECIMAL_RESULT:
          op = &Query_result_max_min_subquery::cmp_decimal;
          break;
        case ROW_RESULT:
        case INVALID_RESULT:
          // This case should never be chosen
          assert(0);
          op = nullptr;
      }
    }
    cache->store(val_item);
    it->store(0, cache);
  }
  it->assigned(true);
  return false;
}

/**
  Compare two floating point numbers for MAX or MIN.

  Compare two numbers and decide if the number should be cached as the
  maximum/minimum number seen this far. If fmax==true, this is a
  comparison for MAX, otherwise it is a comparison for MIN.

  val1 is the new number to compare against the current
  maximum/minimum. val2 is the current maximum/minimum.

  ignore_nulls is used to control behavior when comparing with a NULL
  value. If ignore_nulls==false, the behavior is to store the first
  NULL value discovered (i.e, return true, that it is larger than the
  current maximum) and never replace it. If ignore_nulls==true, NULL
  values are not stored. ANY subqueries use ignore_nulls==true, ALL
  subqueries use ignore_nulls==false.

  @retval true if the new number should be the new maximum/minimum.
  @retval false if the maximum/minimum should stay unchanged.
 */
bool Query_result_max_min_subquery::cmp_real() {
  Item *maxmin = ((Item_singlerow_subselect *)item)->element_index(0);
  double val1 = cache->val_real(), val2 = maxmin->val_real();
  /*
    If we're ignoring NULLs and the current maximum/minimum is NULL
    (must have been placed there as the first value iterated over) and
    the new value is not NULL, return true so that a new, non-NULL
    maximum/minimum is set. Otherwise, return false to keep the
    current non-NULL maximum/minimum.

    If we're not ignoring NULLs and the current maximum/minimum is not
    NULL, return true to store NULL. Otherwise, return false to keep
    the NULL we've already got.
  */
  if (cache->null_value || maxmin->null_value)
    return (ignore_nulls) ? !(cache->null_value) : !(maxmin->null_value);
  return (fmax) ? (val1 > val2) : (val1 < val2);
}

/**
  Compare two integer numbers for MAX or MIN.

  @see Query_result_max_min_subquery::cmp_real()
*/
bool Query_result_max_min_subquery::cmp_int() {
  Item *maxmin = ((Item_singlerow_subselect *)item)->element_index(0);
  longlong val1 = cache->val_int(), val2 = maxmin->val_int();
  if (cache->null_value || maxmin->null_value)
    return (ignore_nulls) ? !(cache->null_value) : !(maxmin->null_value);
  return (fmax) ? (val1 > val2) : (val1 < val2);
}

/**
  Compare two decimal numbers for MAX or MIN.

  @see Query_result_max_min_subquery::cmp_real()
*/
bool Query_result_max_min_subquery::cmp_decimal() {
  Item *maxmin = ((Item_singlerow_subselect *)item)->element_index(0);
  my_decimal cval, *cvalue = cache->val_decimal(&cval);
  my_decimal mval, *mvalue = maxmin->val_decimal(&mval);
  if (cache->null_value || maxmin->null_value)
    return (ignore_nulls) ? !(cache->null_value) : !(maxmin->null_value);
  return (fmax) ? (my_decimal_cmp(cvalue, mvalue) > 0)
                : (my_decimal_cmp(cvalue, mvalue) < 0);
}

/**
  Compare two strings for MAX or MIN.

  @see Query_result_max_min_subquery::cmp_real()
*/
bool Query_result_max_min_subquery::cmp_str() {
  Item *maxmin = down_cast<Item_singlerow_subselect *>(item)->element_index(0);
  /*
    as far as both operand is Item_cache buf1 & buf2 will not be used,
    but added for safety
  */
  String buf1;
  const String *val1 = cache->val_str(&buf1);
  if (current_thd->is_error()) return false;
  String buf2;
  const String *val2 = maxmin->val_str(&buf2);
  if (cache->null_value || maxmin->null_value)
    return (ignore_nulls) ? !(cache->null_value) : !(maxmin->null_value);
  return (fmax) ? (sortcmp(val1, val2, cache->collation.collation) > 0)
                : (sortcmp(val1, val2, cache->collation.collation) < 0);
}

Item_maxmin_subselect::Item_maxmin_subselect(Item_subselect *parent,
                                             Query_block *query_block,
                                             bool max_arg, bool ignore_nulls)
    : Item_singlerow_subselect(), was_values(false) {
  DBUG_TRACE;
  max = max_arg;
  init(query_block, new (*THR_MALLOC) Query_result_max_min_subquery(
                        this, max_arg, ignore_nulls));
  max_columns = 1;
  set_nullable(true);
  max_columns = 1;

  /*
    Following information was collected during performing fix_fields()
    of Items belonged to subquery, which will be not repeated
  */
  used_tables_cache = parent->used_tables();
}

void Item_maxmin_subselect::cleanup() {
  DBUG_TRACE;
  Item_singlerow_subselect::cleanup();

  was_values = false;
}

void Item_maxmin_subselect::print(const THD *thd, String *str,
                                  enum_query_type query_type) const {
  str->append(max ? "<max>" : "<min>", 5);
  Item_singlerow_subselect::print(thd, str, query_type);
}

void Item_singlerow_subselect::reset() {
  null_value = true;
  if (value) value->null_value = true;
}

/**
  @todo
  - We can't change name of Item_field or Item_ref, because it will
  prevent it's correct resolving, but we should save name of
  removed item => we do not make optimization if top item of
  list is field or reference.
  - switch off this optimization for prepare statement,
  because we do not rollback this changes.
  Make rollback for it, or special name resolving mode in 5.0.
*/
bool Item_singlerow_subselect::select_transformer(THD *thd,
                                                  Query_block *select) {
  DBUG_TRACE;
  if (changed) return false;

  Query_block *outer = select->outer_query_block();

  Item *single_field = select->single_visible_field();

  if (single_field != nullptr &&
      single_field->type() == Item::VALUES_COLUMN_ITEM) {
    /*
      A subquery that is a VALUES clause can be used as a scalar subquery.
      But VALUES clauses with a single row are transformed to their simple
      components and will not be shown as VALUES_COLUMN_ITEM here.
    */
    assert(select->row_value_list->size() > 1);
    /*
      Since scalar subqueries can have at most one row, reject VALUES
      clauses (with more than one row) immediately:
    */
    my_error(ER_SUBQUERY_NO_1_ROW, MYF(0));
    return true;
  }
  if (!unit->is_set_operation() && !select->has_tables() &&
      single_field != nullptr && !single_field->has_aggregation() &&
      select->olap == UNSPECIFIED_OLAP_TYPE && !single_field->has_wf() &&
      select->where_cond() == nullptr && select->having_cond() == nullptr) {
    have_to_be_excluded = true;
    if (thd->lex->is_explain()) {
      char warn_buff[MYSQL_ERRMSG_SIZE];
      sprintf(warn_buff, ER_THD(thd, ER_SELECT_REDUCED), select->select_number);
      push_warning(thd, Sql_condition::SL_NOTE, ER_SELECT_REDUCED, warn_buff);
    }
    substitution = single_field;
    if (substitution->type() == SUBSELECT_ITEM) {
      Item_subselect *subs = down_cast<Item_subselect *>(substitution);
      subs->unit->set_explain_marker_from(thd, unit);
    }
    // Merge subquery's name resolution contexts into parent's
    outer->merge_contexts(select);

    // Fix query block contexts after merging the subquery
    substitution->fix_after_pullout(outer, select);
  }
  return false;
}

void Item_singlerow_subselect::store(uint i, Item *item) {
  row[i]->store(item);
  row[i]->cache_value();
}

enum Item_result Item_singlerow_subselect::result_type() const {
  return subquery->type();
}

bool Item_singlerow_subselect::resolve_type(THD *thd) {
  if ((max_columns = unit_cols()) == 1) {
    subquery->fix_length_and_dec(row = &value);
  } else {
    row = thd->mem_root->ArrayAlloc<Item_cache *>(max_columns);
    if (row == nullptr) {
      return true;
    }
    subquery->fix_length_and_dec(row);
    assert(*row != nullptr);
    value = *row;
  }
  set_data_type(subquery->field_type());
  unsigned_flag = value->unsigned_flag;
  /*
    Check if NULL values may be returned by the subquery. Either
    because one or more of the columns could be NULL, or because the
    subquery could return an empty result.
  */
  set_nullable(subquery->may_be_null());
  return false;
}

void Item_singlerow_subselect::no_rows_in_result() {
  /*
    This is only possible if we have a dependent subquery in the SELECT list
    and an aggregated outer query based on zero rows, which is an illegal query
    according to the SQL standard. ONLY_FULL_GROUP_BY rejects such queries.
  */
  if (unit->uncacheable & UNCACHEABLE_DEPENDENT) no_rows = true;
}

bool Item_singlerow_subselect::check_cols(uint c) {
  if (c != unit_cols()) {
    my_error(ER_OPERAND_COLUMNS, MYF(0), c);
    return true;
  }
  return false;
}

bool Item_singlerow_subselect::null_inside() {
  for (uint i = 0; i < max_columns; i++) {
    if (row[i]->null_value) return true;
  }
  return false;
}

void Item_singlerow_subselect::bring_value() {
  if (!exec(current_thd) && assigned())
    null_value = false;
  else
    reset();
}

double Item_singlerow_subselect::val_real() {
  assert(fixed == 1);
  if (!no_rows && !exec(current_thd) && !value->null_value) {
    null_value = false;
    return value->val_real();
  } else {
    reset();
    return error_real();
  }
}

longlong Item_singlerow_subselect::val_int() {
  assert(fixed == 1);
  if (!no_rows && !exec(current_thd) && !value->null_value) {
    null_value = false;
    return value->val_int();
  } else {
    reset();
    return error_int();
  }
}

String *Item_singlerow_subselect::val_str(String *str) {
  if (!no_rows && !exec(current_thd) && !value->null_value) {
    null_value = false;
    return value->val_str(str);
  } else {
    reset();
    return error_str();
  }
}

my_decimal *Item_singlerow_subselect::val_decimal(my_decimal *decimal_value) {
  if (!no_rows && !exec(current_thd) && !value->null_value) {
    my_decimal *retval = value->val_decimal(decimal_value);
    null_value = value->null_value;
    return retval;
  } else {
    reset();
    return error_decimal(decimal_value);
  }
}

bool Item_singlerow_subselect::val_json(Json_wrapper *result) {
  if (!no_rows && !exec(current_thd) && !value->null_value) {
    null_value = false;
    return value->val_json(result);
  } else {
    reset();
    return current_thd->is_error();
  }
}

bool Item_singlerow_subselect::get_date(MYSQL_TIME *ltime,
                                        my_time_flags_t fuzzydate) {
  if (!no_rows && !exec(current_thd) && !value->null_value) {
    null_value = false;
    return value->get_date(ltime, fuzzydate);
  } else {
    reset();
    return true;
  }
}

bool Item_singlerow_subselect::get_time(MYSQL_TIME *ltime) {
  if (!no_rows && !exec(current_thd) && !value->null_value) {
    null_value = false;
    return value->get_time(ltime);
  } else {
    reset();
    return true;
  }
}

bool Item_singlerow_subselect::val_bool() {
  if (!no_rows && !exec(current_thd) && !value->null_value) {
    null_value = false;
    return value->val_bool();
  } else {
    reset();
    return false;
  }
}

/* EXISTS subselect interface class */
class Query_result_exists_subquery : public Query_result_subquery {
 public:
  explicit Query_result_exists_subquery(Item_subselect *item_arg)
      : Query_result_subquery(item_arg) {}
  bool send_data(THD *thd, const mem_root_deque<Item *> &items) override;
};

bool Query_result_exists_subquery::send_data(THD *,
                                             const mem_root_deque<Item *> &) {
  DBUG_TRACE;
  Item_exists_subselect *it = (Item_exists_subselect *)item;
  /*
    A subquery may be evaluated 1) by executing the JOIN 2) by optimized
    functions (index_subquery, subquery materialization).
    It's only in (1) that we get here when we find a row. In (2) "value" is
    set elsewhere.
  */
  it->value = true;
  it->assigned(true);
  return false;
}

Item_exists_subselect::Item_exists_subselect(Query_block *select)
    : Item_subselect() {
  DBUG_TRACE;
  init(select, new (*THR_MALLOC) Query_result_exists_subquery(this));
  max_columns = UINT_MAX;
  null_value = false;   // can't be NULL
  set_nullable(false);  // can't be NULL
}

void Item_exists_subselect::print(const THD *thd, String *str,
                                  enum_query_type query_type) const {
  const char *tail = Item_bool_func::bool_transform_names[value_transform];
  if (implicit_is_op) tail = "";
  // Put () around NOT as it has lower associativity than IS TRUE, or '+'
  if (value_transform == BOOL_NEGATED) str->append(STRING_WITH_LEN("(not "));
  str->append(STRING_WITH_LEN("exists"));
  Item_subselect::print(thd, str, query_type);
  if (value_transform == BOOL_NEGATED) str->append(STRING_WITH_LEN(")"));
  if (tail[0]) {
    str->append(STRING_WITH_LEN(" "));
    str->append(tail, strlen(tail));
  }
}

/**
  Translates the value of the naked EXISTS to a value taking into account the
  optional NULL and IS [NOT] TRUE/FALSE.
  @param[in,out] null_v      NULL state of the value
  @param         v           TRUE/FALSE state of the value
*/
bool Item_exists_subselect::translate(bool &null_v, bool v) {
  if (null_v)  // Naked IN returns UNKNOWN
  {
    assert(substype() != EXISTS_SUBS);
    switch (value_transform) {
      case BOOL_IDENTITY:
      case BOOL_NEGATED:
        return false;
      case BOOL_IS_TRUE:
      case BOOL_IS_FALSE:
        null_v = false;
        return false;
      case BOOL_NOT_TRUE:
      case BOOL_NOT_FALSE:
        null_v = false;
        return true;
      default:
        assert(false);
        return false;
    }
  }
  // Naked IN returns 'v'
  switch (value_transform) {
    case BOOL_IDENTITY:
    case BOOL_IS_TRUE:
    case BOOL_NOT_FALSE:
      return v;
    case BOOL_NEGATED:
    case BOOL_NOT_TRUE:
    case BOOL_IS_FALSE:
      return !v;
    default:
      assert(false);
      return v;
  }
}

Item *Item_exists_subselect::truth_transformer(THD *, enum Bool_test test) {
  // ALL_SUBS, ANY_SUBS are always wrapped in Item_func_{not|nop}_all
  // so never come here. Which is good as they don't support all possible
  // value transforms.
  assert(substype() == EXISTS_SUBS || substype() == IN_SUBS);
  switch (test) {
    case BOOL_NEGATED:
    case BOOL_IS_TRUE:
    case BOOL_IS_FALSE:
    case BOOL_NOT_TRUE:
    case BOOL_NOT_FALSE:
      break;
    default:
      assert(false);
  }
  // x IN (SELECT y FROM DUAL) may be replaced with x=y which alas doesn't
  // support value transforms; we still want to allow this replacement, so
  // let's not store the value transform in that case, and keep an explicit
  // truth test Item at the outside.
  if (!unit->is_set_operation() && !unit->first_query_block()->has_tables() &&
      unit->first_query_block()->where_cond() == nullptr &&
      substype() == IN_SUBS &&
      unit->first_query_block()->single_visible_field() != nullptr)
    return nullptr;

  // Combine requested test with already present test, if any.
  value_transform = Item_bool_func::bool_transform[value_transform][test];
  return this;
}

bool Item_in_subselect::test_limit() {
  for (auto qt : unit->query_terms<QTC_PRE_ORDER>())
    if (qt->query_block()->test_limit()) return true;
  return false;
}

Item_in_subselect::Item_in_subselect(Item *left_exp, Query_block *select)
    : Item_exists_subselect(),
      left_expr(left_exp),
      left_expr_cache(nullptr),
      left_expr_cache_filled(false),
      need_expr_cache(true),
      m_injected_left_expr(nullptr),
      optimizer(nullptr),
      was_null(false),
      abort_on_null(false),
      in2exists_info(nullptr),
      pushed_cond_guards(nullptr),
      upper_item(nullptr) {
  DBUG_TRACE;
  init(select, new (*THR_MALLOC) Query_result_exists_subquery(this));
  max_columns = UINT_MAX;
  set_nullable(true);
  reset();
  // if test_limit will fail then error will be reported to client
  test_limit();
}

Item_in_subselect::Item_in_subselect(const POS &pos, Item *left_exp,
                                     PT_subquery *pt_subquery_arg)
    : super(pos),
      left_expr(left_exp),
      left_expr_cache(nullptr),
      left_expr_cache_filled(false),
      need_expr_cache(true),
      m_injected_left_expr(nullptr),
      optimizer(nullptr),
      was_null(false),
      abort_on_null(false),
      in2exists_info(nullptr),
      pushed_cond_guards(nullptr),
      upper_item(nullptr),
      pt_subselect(pt_subquery_arg) {
  DBUG_TRACE;
  max_columns = UINT_MAX;
  set_nullable(true);
  reset();
}

bool Item_in_subselect::itemize(Parse_context *pc, Item **res) {
  if (skip_itemize(res)) return false;
  if (super::itemize(pc, res) || left_expr->itemize(pc, &left_expr) ||
      pt_subselect->contextualize(pc))
    return true;
  Query_block *query_block = pt_subselect->value();
  init(query_block, new (*THR_MALLOC) Query_result_exists_subquery(this));
  if (test_limit()) return true;
  return false;
}

Item_allany_subselect::Item_allany_subselect(Item *left_exp,
                                             chooser_compare_func_creator fc,
                                             Query_block *select, bool all_arg)
    : Item_in_subselect(), func_creator(fc), all(all_arg) {
  DBUG_TRACE;
  left_expr = left_exp;
  func = func_creator(all_arg);
  init(select, new (*THR_MALLOC) Query_result_exists_subquery(this));
  max_columns = 1;
  reset();
  // if test_limit will fail then error will be reported to client
  test_limit();
}

bool Item_exists_subselect::resolve_type(THD *thd) {
  set_data_type_longlong();
  max_length = 1;
  max_columns = unit_cols();
  if (strategy == Subquery_strategy::SUBQ_EXISTS) {
    Prepared_stmt_arena_holder ps_arena_holder(thd);
    /*
      We need only 1 row to determine existence if LIMIT is not 0.
      Note that if the subquery is "SELECT1 UNION SELECT2" then this is not
      working optimally (Bug#14215895).
    */
    if (unit->global_parameters()->select_limit == nullptr ||
        unit->global_parameters()->select_limit->val_uint() > 0) {
      unit->global_parameters()->select_limit = new Item_int(1);
      if (unit->global_parameters()->select_limit == nullptr) return true;
      unit->global_parameters()->m_internal_limit = true;
    }
  }
  return false;
}

/**
   Helper for resolve_subquery().

   @returns true if semijoin or antijoin is allowed; if returning true, also
   records in the Item's can_do_aj member if this will be an antijoin (true)
   or semijoin (false) nest.
*/
bool Item_exists_subselect::choose_semijoin_or_antijoin() {
  can_do_aj = false;
  [[maybe_unused]] bool might_do_sj = false, might_do_aj = false;
  bool null_problem = false;
  switch (value_transform) {
    case BOOL_IS_TRUE:
      might_do_sj = true;
      break;
    case BOOL_NOT_TRUE:
      might_do_aj = true;
      break;
    case BOOL_IS_FALSE:
      might_do_aj = true;
      null_problem = true;
      break;
    case BOOL_NOT_FALSE:
      might_do_sj = true;
      null_problem = true;
      break;
    default:
      return false;
  }
  assert((might_do_sj ^ might_do_aj) == 1);
  if (substype() == EXISTS_SUBS)  // never returns NULL
    null_problem = false;
  if (null_problem) {
    // antijoin/semijoin cannot work with NULLs on either side of IN
    if (down_cast<Item_in_subselect *>(this)->left_expr->is_nullable())
      return false;
    for (Item *inner : unit->first_query_block()->visible_fields()) {
      if (inner->is_nullable()) return false;
    }
  }
  can_do_aj = might_do_aj;
  return true;
}

double Item_exists_subselect::val_real() { return val_bool(); }

longlong Item_exists_subselect::val_int() { return val_bool(); }

/**
  Return the result of EXISTS as a string value

  Converts the true/false result into a string value.

  @param [out] str             buffer to hold the resulting string value
  @retval                      Pointer to the converted string.
                               NULL if execution returns in error
*/

String *Item_exists_subselect::val_str(String *str) {
  longlong val = val_bool();
  if (null_value) return nullptr;
  str->set(val, &my_charset_bin);
  return str;
}

/**
  Return the result of EXISTS as a decimal value

  Converts the true/false result into a decimal value.

  @param [out] decimal_value   Buffer to hold the resulting decimal value
  @retval                      Pointer to the converted decimal.
                               NULL if execution returns in error
*/

my_decimal *Item_exists_subselect::val_decimal(my_decimal *decimal_value) {
  longlong val = val_bool();
  if (null_value) return nullptr;
  int2my_decimal(E_DEC_FATAL_ERROR, val, false, decimal_value);
  return decimal_value;
}

bool Item_exists_subselect::val_bool() {
  assert(fixed);
  if (exec(current_thd)) {
    reset();
    return false;
  }
  // EXISTS can never return NULL value
  assert(!null_value);
  return translate(null_value, value);
}

double Item_in_subselect::val_real() {
  // Substituted with Item_in_optimizer, so this function is never used
  assert(false);
  my_error(ER_INTERNAL_ERROR, MYF(0), "Invalid function call");
  return error_real();
}

longlong Item_in_subselect::val_int() {
  // Substituted with Item_in_optimizer, so this function is never used
  assert(false);
  my_error(ER_INTERNAL_ERROR, MYF(0), "Invalid function call");
  return error_int();
}

String *Item_in_subselect::val_str(String *) {
  // Substituted with Item_in_optimizer, so this function is never used
  assert(false);
  my_error(ER_INTERNAL_ERROR, MYF(0), "Invalid function call");
  return error_str();
}

bool Item_in_subselect::val_bool() {
  // Substituted with Item_in_optimizer, so this function is never used
  assert(false);
  my_error(ER_INTERNAL_ERROR, MYF(0), "Invalid function call");
  return error_int();
}

bool Item_in_subselect::val_bool_naked() {
  assert(fixed);
  if (exec(current_thd)) {
    reset();
    return false;
  }
  if (was_null && !value) null_value = true;
  /*
    This is the value of the naked IN. Negation, or applying of IS TRUE/FALSE,
    is left to the parent Item_in_optimizer, so make sure it's there:
  */
  assert(optimizer);
  return value;
}

my_decimal *Item_in_subselect::val_decimal(my_decimal *) {
  // Substituted with Item_in_optimizer, so this function is never used
  assert(false);
  my_error(ER_INTERNAL_ERROR, MYF(0), "Invalid function call");
  return nullptr;
}

/**
  Rewrite a single-column IN/ALL/ANY subselect

  DESCRIPTION
    Rewrite a single-column subquery using rule-based approach. The subquery

       oe $cmp$ (SELECT ie FROM ... WHERE subq_where ... HAVING subq_having)

    First, try to convert the subquery to scalar-result subquery in one of
    the forms:

       - oe $cmp$ (SELECT MAX(...) )  // handled by Item_singlerow_subselect
       - oe $cmp$ \<max\>(SELECT ...)   // handled by Item_maxmin_subselect

    If that fails, the subquery will be handled with class Item_in_optimizer.
    There are two possibilities:
    - If the subquery execution method is materialization, then the subquery is
      not transformed any further.
    - Otherwise the IN predicates is transformed into EXISTS by injecting
      equi-join predicates and possibly other helper predicates. For details
      see method single_value_in_like_transformer().

  @param thd    Thread handle
  @param select Query block of the subquery
  @param func   Subquery comparison creator

  @returns false if success, true if error
*/

bool Item_in_subselect::single_value_transformer(THD *thd, Query_block *select,
                                                 Comp_creator *func) {
  bool subquery_maybe_null = false;
  DBUG_TRACE;

  /*
    Check that the right part of the subselect contains no more than one
    column. E.g. in SELECT 1 IN (SELECT * ..) the right part is (SELECT * ...)
  */
  // psergey: duplicated_subselect_card_check
  if (select->num_visible_fields() > 1) {
    my_error(ER_OPERAND_COLUMNS, MYF(0), 1);
    return true;
  }

  /*
    Check the nullability of the subquery. The subquery should return
    only one column, so we check the nullability of the first item in
    Query_block::fields_list. In case the subquery is a union, check the
    nullability of the first item of each query block belonging to the
    union.
  */
  for (Query_block *sel = unit->first_query_block(); sel != nullptr;
       sel = sel->next_query_block()) {
    Item *only_item = sel->single_visible_field();
    if (only_item == nullptr) {
      // There was more than one after all.
      my_error(ER_OPERAND_COLUMNS, MYF(0), 1);
      return true;
    }
    if ((subquery_maybe_null = only_item->is_nullable())) break;
  }
  /*
    If this is an ALL/ANY single-value subquery predicate, try to rewrite
    it with a MIN/MAX subquery.

    E.g. SELECT * FROM t1 WHERE b > ANY (SELECT a FROM t2) can be rewritten
    with SELECT * FROM t1 WHERE b > (SELECT MIN(a) FROM t2).

    A predicate may be transformed to use a MIN/MAX subquery if it:
    1. has a greater than/less than comparison operator, and
    2. is not correlated with the outer query, and
    3. UNKNOWN results are treated as FALSE, by this item or the outer item,
    or can never be generated.
  */
  if (!func->eqne_op() &&                                                // 1
      !unit->uncacheable &&                                              // 2
      (abort_on_null || (upper_item && upper_item->ignore_unknown()) ||  // 3
       (!left_expr->is_nullable() && !subquery_maybe_null))) {
    if (substitution != nullptr) {
      // It is second (third, ...) query block of set operation => All is done
      return false;
    }

    Item *subquery;
    if (!select->is_explicitly_grouped() && select->having_cond() == nullptr &&
        // MIN/MAX(agg_or_window_func) would not be valid
        !select->with_sum_func && !select->has_windows() &&
        !(select->next_query_block()) && select->has_tables() &&
        // For ALL: MIN ignores NULL: 3<=ALL(4 and NULL) is UNKNOWN, while
        // NOT(3>(SELECT MIN(4 and NULL)) is TRUE
        !(substype() == ALL_SUBS && subquery_maybe_null)) {
      OPT_TRACE_TRANSFORM(&thd->opt_trace, oto0, oto1, select->select_number,
                          "> ALL/ANY (SELECT)", "SELECT(MIN)");
      oto1.add("chosen", true);
      thd->lex->m_subquery_to_derived_is_impossible = true;
      Item_sum_hybrid *item;
      nesting_map save_allow_sum_func;
      if (func->l_op()) {
        /*
          (ALL && (> || =>)) || (ANY && (< || =<))
          for ALL condition is inverted
        */
        item = new Item_sum_max(select->base_ref_items[0]);
      } else {
        /*
          (ALL && (< || =<)) || (ANY && (> || =>))
          for ALL condition is inverted
        */
        item = new Item_sum_min(select->base_ref_items[0]);
      }
      if (item == nullptr) return true;
      if (upper_item) upper_item->set_sum_test(item);
      select->base_ref_items[0] = item;

      // Find the correct position in the field list, and overwrite it with the
      // item.
      for (auto it = select->visible_fields().begin();
           it != select->visible_fields().end(); ++it) {
        *it = item;
        break;
      }

      DBUG_EXECUTE("where", print_where(thd, item, "rewrite with MIN/MAX",
                                        QT_ORDINARY););

      save_allow_sum_func = thd->lex->allow_sum_func;
      thd->lex->allow_sum_func |= (nesting_map)1 << select->nest_level;
      /*
        Item_sum_(max|min) can't substitute other item => we can use 0 as
        reference, also Item_sum_(max|min) can't be fixed after creation, so
        we do not check item->fixed
      */
      if (item->fix_fields(thd, nullptr)) return true;
      thd->lex->allow_sum_func = save_allow_sum_func;

      subquery = new Item_singlerow_subselect(select);
      if (subquery == nullptr) return true;
    } else {
      OPT_TRACE_TRANSFORM(&thd->opt_trace, oto0, oto1, select->select_number,
                          "> ALL/ANY (SELECT)", "MIN (SELECT)");
      oto1.add("chosen", true);
      Item_maxmin_subselect *item = new Item_maxmin_subselect(
          this, select, func->l_op(), substype() == ANY_SUBS);
      if (item == nullptr) return true;
      subquery = item;
      if (upper_item) upper_item->set_sub_test(item);
    }
    if (upper_item) upper_item->set_subselect(this);

    substitution = func->create(left_expr, subquery);
    if (substitution == nullptr) return true;

    return false;
  }

  if (substitution == nullptr) {
    // Invoked for the first or only query block in the subquery's query expr
    substitution = optimizer;

    thd->lex->set_current_query_block(select->outer_query_block());
    // optimizer never use Item **ref => we can pass 0 as parameter
    assert(optimizer != nullptr);
    if (optimizer->fix_left(thd, nullptr)) return true;
    thd->lex->set_current_query_block(select);

    /*
      As far as  Item_ref_in_optimizer do not substitute itself on fix_fields
      we can use same item for all query blocks.
    */
    Item_ref *const left = new Item_ref(
        &select->context, (Item **)optimizer->get_cache(), in_left_expr_name);
    if (left == nullptr) return true;

    if (mark_as_outer(left_expr, 0))
      left->depended_from = select->outer_query_block();

    m_injected_left_expr = left;

    assert(in2exists_info == nullptr);
    in2exists_info = new (thd->mem_root) In2exists_info;
    if (in2exists_info == nullptr) return true;
    in2exists_info->dependent_before =
        unit->uncacheable & UNCACHEABLE_DEPENDENT;
    if (!left_expr->const_item()) unit->uncacheable |= UNCACHEABLE_DEPENDENT;
    in2exists_info->dependent_after = unit->uncacheable & UNCACHEABLE_DEPENDENT;
  }

  if (!abort_on_null && left_expr->is_nullable() &&
      pushed_cond_guards == nullptr) {
    pushed_cond_guards = (bool *)thd->alloc(sizeof(bool));
    if (pushed_cond_guards == nullptr) return true;
    pushed_cond_guards[0] = true;
  }

  /* Perform the IN=>EXISTS transformation. */
  return single_value_in_to_exists_transformer(thd, select, func);
}

/**
  Transform an IN predicate into EXISTS via predicate injection.

  @details The transformation injects additional predicates into the subquery
  (and makes the subquery correlated) as follows.

  - If the subquery has aggregates, GROUP BY, or HAVING, convert to

    SELECT ie FROM ...  HAVING subq_having AND
                               trigcond(oe $cmp$ ref_or_null_helper<ie>)

    the addition is wrapped into trigger only when we want to distinguish
    between NULL and FALSE results.

  - Otherwise (no aggregates/GROUP BY/HAVING) convert it to one of the
    following:

    = If we don't need to distinguish between NULL and FALSE subquery:

      SELECT 1 FROM ... WHERE (oe $cmp$ ie) AND subq_where

    = If we need to distinguish between those:

      SELECT 1 FROM ...
        WHERE  subq_where AND trigcond((oe $cmp$ ie) OR (ie IS NULL))
        HAVING trigcond(@<is_not_null_test@>(ie))

  At JOIN::optimize() we will compare costs of materialization and EXISTS; if
  the former is cheaper we will switch to it.

    @param thd    Thread handle
    @param select Query block of the subquery
    @param func   Subquery comparison creator

    @returns false if success, true if error
             Success means that appropriate predicates were injected into
             the query block of the subquery predicate, or the subquery
             predicate was reduced to a simple predicate.
*/

bool Item_in_subselect::single_value_in_to_exists_transformer(
    THD *thd, Query_block *select, Comp_creator *func) {
  DBUG_TRACE;

  Query_block *outer = select->outer_query_block();

  OPT_TRACE_TRANSFORM(&thd->opt_trace, oto0, oto1, select->select_number,
                      "IN (SELECT)", "EXISTS (CORRELATED SELECT)");
  oto1.add("chosen", true);

  // Transformation will make the subquery a dependent one.
  if (!left_expr->const_item()) select->uncacheable |= UNCACHEABLE_DEPENDENT;

  in2exists_info->added_to_where = false;

  if (select->having_cond() != nullptr || select->is_explicitly_grouped() ||
      select->with_sum_func || select->has_windows()) {
    Item_ref_null_helper *ref_null = new Item_ref_null_helper(
        &select->context, this, &select->base_ref_items[0]);
    Item_bool_func *item = func->create(m_injected_left_expr, ref_null);
    if (item == nullptr) return true;
    item->set_created_by_in2exists();

    /*
      Assume that the expression in the SELECT list, is a function of a group
      aggregate which is aggregated in an outer query, for example
      SELECT ... FROM t1 WHERE t1.b IN (SELECT <expr of SUM(t1.a)> FROM t2). We
      are changing it to
      SELECT ... FROM t1 WHERE t1.b IN (SELECT <expr of SUM(t1.a)> FROM t2
                                        HAVING t1.b=ref-to-<expr of SUM(t1.a)>).
      SUM is an "inner sum func", its fix_fields() has added it to
      inner_sum_func_list of the outer query; the outer query will do
      split_sum_func on it which will add SUM as a hidden item and replace it
      in 'expr' with a pointer to an Item_ref.
      If 'expr' is a function which has SUM as one of its arguments, the
      SELECT list and HAVING access 'expr' through two different pointers, but
      there's only one 'expr' Item, which accesses SUM through one pointer, so
      there's a single referenced_by pointer to remember, we use
      referenced_by[0]. But if 'expr' is directly the SUM, with no Item in
      between, then there are two places where 'expr' should be replaced: the
      iterator in the SELECT list, and the 'ref-to-expr' in HAVING above. So we
      have to document those 2 places in referenced_by[0] and referenced_by[1].
    */
    Item *selected = select->base_ref_items[0];
    if (selected->type() == SUM_FUNC_ITEM) {
      Item_sum *selected_sum = down_cast<Item_sum *>(selected);
      if (!selected_sum->referenced_by[0])
        selected_sum->referenced_by[0] = ref_null->ref_pointer();
      else {
        // Slot 0 already occupied, use 1.
        assert(!selected_sum->referenced_by[1]);
        selected_sum->referenced_by[1] = ref_null->ref_pointer();
      }
    }
    if (!abort_on_null && left_expr->is_nullable()) {
      /*
        We can encounter "NULL IN (SELECT ...)". Wrap the added condition
        within a trig_cond.
      */
      item =
          new Item_func_trig_cond(item, get_cond_guard(0), nullptr, NO_PLAN_IDX,
                                  Item_func_trig_cond::OUTER_FIELD_IS_NOT_NULL);
      if (item == nullptr) return true;
      item->set_created_by_in2exists();
    }

    /*
      AND and comparison functions can't be changed during fix_fields()
      we can assign query_block->having_cond here, and pass NULL as last
      argument (reference) to fix_fields()
    */
    select->set_having_cond(and_items(select->having_cond(), item));
    select->having_cond()->apply_is_true();
    select->having_fix_field = true;
    /*
      we do not check having_cond()->fixed, because Item_and (from and_items)
      or comparison function (from func->create) can't be fixed after creation
    */
    Opt_trace_array having_trace(&thd->opt_trace,
                                 "evaluating_constant_having_conditions");
    if (select->having_cond()->fix_fields(thd, nullptr)) return true;
    select->having_fix_field = false;
  } else {
    Item *orig_item = select->single_visible_field();

    if (!select->source_table_is_one_row() || select->where_cond() != nullptr) {
      Item_bool_func *item = func->create(m_injected_left_expr, orig_item);
      if (item == nullptr) return true;
      /*
        We may soon add a 'OR inner IS NULL' to 'item', but that may later be
        removed if 'inner' is not nullable, so the in2exists mark must be on
        'item' too. Not only on the OR node.
      */
      item->set_created_by_in2exists();
      if (!abort_on_null && orig_item->is_nullable()) {
        Item_bool_func *having = new Item_is_not_null_test(this, orig_item);
        if (having == nullptr) return true;
        having->set_created_by_in2exists();
        if (left_expr->is_nullable()) {
          having = new Item_func_trig_cond(
              having, get_cond_guard(0), nullptr, NO_PLAN_IDX,
              Item_func_trig_cond::OUTER_FIELD_IS_NOT_NULL);
          if (having == nullptr) return true;
          having->set_created_by_in2exists();
        }
        /*
          Item_is_not_null_test can't be changed during fix_fields()
          we can assign query_block->having_cond() here, and pass NULL as last
          argument (reference) to fix_fields()
        */
        select->set_having_cond(having);
        select->having_fix_field = true;
        /*
          No need to check query_block->having_cond()->fixed, because Item_and
          (from and_items) or comparison function (from func->create)
          can't be fixed after creation.
        */
        Opt_trace_array having_trace(&thd->opt_trace,
                                     "evaluating_constant_having_conditions");
        if (select->having_cond()->fix_fields(thd, nullptr)) return true;
        select->having_fix_field = false;
        item = new Item_cond_or(item, new Item_func_isnull(orig_item));
        if (item == nullptr) return true;
        item->set_created_by_in2exists();
      }
      /*
        If we may encounter NULL IN (SELECT ...) and care whether subquery
        result is NULL or FALSE, wrap condition in a trig_cond.
      */
      if (!abort_on_null && left_expr->is_nullable()) {
        item = new Item_func_trig_cond(
            item, get_cond_guard(0), nullptr, NO_PLAN_IDX,
            Item_func_trig_cond::OUTER_FIELD_IS_NOT_NULL);
        if (item == nullptr) return true;
        item->set_created_by_in2exists();
      }
      /*
        AND can't be changed during fix_fields()
        we can assign query_block->having_cond() here, and pass NULL as last
        argument (reference) to fix_fields()

        Note that if query_block is the fake one of UNION, it does not make
        much sense to give it a WHERE clause below... we already give one to
        each member of the UNION.
      */
      select->set_where_cond(and_items(select->where_cond(), item));
      select->where_cond()->apply_is_true();
      in2exists_info->added_to_where = true;
      /*
        No need to check query_block->where_cond()->fixed, because Item_and
        can't be fixed after creation.
      */
      Opt_trace_array where_trace(&thd->opt_trace,
                                  "evaluating_constant_where_conditions");
      if (select->where_cond()->fix_fields(thd, nullptr)) return true;
    } else {
      if (unit->is_set_operation()) {
        /*
          comparison functions can't be changed during fix_fields()
          we can assign query_block->having_cond() here, and pass NULL as last
          argument (reference) to fix_fields()
        */
        Item_bool_func *new_having =
            func->create(m_injected_left_expr,
                         new Item_ref_null_helper(&select->context, this,
                                                  &select->base_ref_items[0]));
        if (new_having == nullptr) return true;
        new_having->set_created_by_in2exists();
        if (!abort_on_null && left_expr->is_nullable()) {
          new_having = new Item_func_trig_cond(
              new_having, get_cond_guard(0), nullptr, NO_PLAN_IDX,
              Item_func_trig_cond::OUTER_FIELD_IS_NOT_NULL);
          if (new_having == nullptr) return true;
          new_having->set_created_by_in2exists();
        }
        select->set_having_cond(new_having);
        select->having_fix_field = true;

        /*
          No need to check query_block->having_cond()->fixed, because comparison
          function (from func->create) can't be fixed after creation.
        */
        Opt_trace_array having_trace(&thd->opt_trace,
                                     "evaluating_constant_having_conditions");
        if (select->having_cond()->fix_fields(thd, nullptr)) return true;
        select->having_fix_field = false;
      } else {
        /*
          Single query block, without tables, without WHERE, HAVING, LIMIT:
          its content has one row and is equal to the item in the SELECT list,
          so we can replace the IN(subquery) with an equality.
          Keep applicability conditions in sync with
          Item_exists_subselect::truth_transformer().
          The expression is moved to the immediately outer query block, so it
          may no longer contain outer references.
        */
        outer->merge_contexts(select);
        orig_item->fix_after_pullout(outer, select);

        // Resolving of substitution item will be done in time of substituting
        substitution = func->create(left_expr, orig_item);
        if (substitution == nullptr) return true;
        have_to_be_excluded = true;
        if (thd->lex->is_explain()) {
          char warn_buff[MYSQL_ERRMSG_SIZE];
          sprintf(warn_buff, ER_THD(thd, ER_SELECT_REDUCED),
                  select->select_number);
          push_warning(thd, Sql_condition::SL_NOTE, ER_SELECT_REDUCED,
                       warn_buff);
        }
        return false;
      }
    }
  }

  thd->lex->m_subquery_to_derived_is_impossible = true;
  return false;
}

bool Item_in_subselect::row_value_transformer(THD *thd, Query_block *select) {
  uint cols_num = left_expr->cols();

  DBUG_TRACE;

  // psergey: duplicated_subselect_card_check
  if (select->num_visible_fields() != left_expr->cols()) {
    my_error(ER_OPERAND_COLUMNS, MYF(0), left_expr->cols());
    return true;
  }

  /*
    Wrap the current IN predicate in an Item_in_optimizer. The actual
    substitution in the Item tree takes place in Item_subselect::fix_fields.
  */
  if (substitution == nullptr) {
    // first call for this query expression
    substitution = optimizer;

    thd->lex->set_current_query_block(select->outer_query_block());
    // optimizer never use Item **ref => we can pass 0 as parameter
    assert(optimizer != nullptr);
    if (optimizer->fix_left(thd, nullptr)) return true;

    thd->lex->set_current_query_block(select);
    assert(in2exists_info == nullptr);
    in2exists_info = new (thd->mem_root) In2exists_info;
    if (in2exists_info == nullptr) return true;
    in2exists_info->dependent_before =
        unit->uncacheable & UNCACHEABLE_DEPENDENT;
    if (!left_expr->const_item()) unit->uncacheable |= UNCACHEABLE_DEPENDENT;
    in2exists_info->dependent_after = unit->uncacheable & UNCACHEABLE_DEPENDENT;

    if (!abort_on_null && left_expr->is_nullable() && !pushed_cond_guards) {
      pushed_cond_guards = (bool *)thd->alloc(sizeof(bool) * left_expr->cols());
      if (pushed_cond_guards == nullptr) return true;
      for (uint i = 0; i < cols_num; i++) {
        pushed_cond_guards[i] = true;
      }
    }
  }

  // Perform the IN=>EXISTS transformation.
  return row_value_in_to_exists_transformer(thd, select);
}

/**
  Transform a (possibly non-correlated) IN subquery into a correlated EXISTS.

  @todo
  The IF-ELSE below can be refactored so that there is no duplication of the
  statements that create the new conditions. For this we have to invert the IF
  and the FOR statements as this:
  for (each left operand)
    create the equi-join condition
    if (is_having_used || !abort_on_null)
      create the "is null" and is_not_null_test items
    if (is_having_used)
      add the equi-join and the null tests to HAVING
    else
      add the equi-join and the "is null" to WHERE
      add the is_not_null_test to HAVING
*/

bool Item_in_subselect::row_value_in_to_exists_transformer(
    THD *thd, Query_block *select) {
  thd->lex->m_subquery_to_derived_is_impossible = true;
  Item_bool_func *having_item = nullptr;
  uint cols_num = left_expr->cols();
  bool is_having_used =
      select->having_cond() != nullptr || select->is_explicitly_grouped() ||
      select->with_sum_func || !select->has_tables() || select->has_windows();

  DBUG_TRACE;
  OPT_TRACE_TRANSFORM(&thd->opt_trace, oto0, oto1, select->select_number,
                      "IN (SELECT)", "EXISTS (CORRELATED SELECT)");
  oto1.add("chosen", true);

  // Transformation will make the subquery a dependent one.
  if (!left_expr->const_item()) select->uncacheable |= UNCACHEABLE_DEPENDENT;
  in2exists_info->added_to_where = false;

  if (is_having_used) {
    /*
      (l1, l2, l3) IN (SELECT v1, v2, v3 ... HAVING having) =>
      EXISTS (SELECT ... HAVING having and
                                (l1 = v1 or is null v1) and
                                (l2 = v2 or is null v2) and
                                (l3 = v3 or is null v3) and
                                is_not_null_test(v1) and
                                is_not_null_test(v2) and
                                is_not_null_test(v3))
      where is_not_null_test used to register nulls in case if we have
      not found matching to return correct NULL value
      TODO: say here explicitly if the order of AND parts matters or not.
    */
    Item_bool_func *item_having_part2 = nullptr;
    for (uint i = 0; i < cols_num; i++) {
      Item *item_i = select->base_ref_items[i];
      Item **pitem_i = &select->base_ref_items[i];
      assert((left_expr->fixed && item_i->fixed) ||
             (item_i->type() == REF_ITEM &&
              ((Item_ref *)(item_i))->ref_type() == Item_ref::OUTER_REF));
      if (item_i->check_cols(left_expr->element_index(i)->cols())) return true;
      Item_ref *const left =
          new Item_ref(&select->context, (*optimizer->get_cache())->addr(i),
                       in_left_expr_name);
      if (left == nullptr) return true; /* purecov: inspected */

      if (mark_as_outer(left_expr, i))
        left->depended_from = select->outer_query_block();

      Item_bool_func *item_eq = new Item_func_eq(
          left, new Item_ref(&select->context, pitem_i, "<list ref>"));
      if (item_eq == nullptr) return true;
      item_eq->set_created_by_in2exists();
      Item_bool_func *item_isnull = new Item_func_isnull(
          new Item_ref(&select->context, pitem_i, "<list ref>"));
      if (item_isnull == nullptr) return true;
      item_isnull->set_created_by_in2exists();
      Item_bool_func *col_item = new Item_cond_or(item_eq, item_isnull);
      if (col_item == nullptr) return true;
      col_item->set_created_by_in2exists();
      if (!abort_on_null && left_expr->element_index(i)->is_nullable()) {
        col_item = new Item_func_trig_cond(
            col_item, get_cond_guard(i), nullptr, NO_PLAN_IDX,
            Item_func_trig_cond::OUTER_FIELD_IS_NOT_NULL);
        if (col_item == nullptr) return true;
        col_item->set_created_by_in2exists();
      }

      having_item = and_items(having_item, col_item);
      if (having_item == nullptr) return true;
      having_item->set_created_by_in2exists();
      Item_bool_func *item_nnull_test = new Item_is_not_null_test(
          this, new Item_ref(&select->context, pitem_i, "<list ref>"));
      if (item_nnull_test == nullptr) return true;
      item_nnull_test->set_created_by_in2exists();
      if (!abort_on_null && left_expr->element_index(i)->is_nullable()) {
        item_nnull_test = new Item_func_trig_cond(
            item_nnull_test, get_cond_guard(i), nullptr, NO_PLAN_IDX,
            Item_func_trig_cond::OUTER_FIELD_IS_NOT_NULL);
        if (item_nnull_test == nullptr) return true;
        item_nnull_test->set_created_by_in2exists();
      }
      item_having_part2 = and_items(item_having_part2, item_nnull_test);
      if (item_having_part2 == nullptr) return true;
      item_having_part2->set_created_by_in2exists();
    }
    having_item = and_items(having_item, item_having_part2);
    if (having_item == nullptr) return true;
    having_item->set_created_by_in2exists();
    having_item->apply_is_true();
  } else {
    /*
      (l1, l2, l3) IN (SELECT v1, v2, v3 ... WHERE where) =>
      EXISTS (SELECT ... WHERE where and
                               (l1 = v1 or is null v1) and
                               (l2 = v2 or is null v2) and
                               (l3 = v3 or is null v3)
                         HAVING is_not_null_test(v1) and
                                is_not_null_test(v2) and
                                is_not_null_test(v3))
      where is_not_null_test register NULLs values but reject rows

      in case when we do not need correct NULL, we have a simpler construction:
      EXISTS (SELECT ... WHERE where and
                               (l1 = v1) and
                               (l2 = v2) and
                               (l3 = v3)
    */
    Item_bool_func *where_item = nullptr;
    for (uint i = 0; i < cols_num; i++) {
      Item *item_i = select->base_ref_items[i];
      Item **pitem_i = &select->base_ref_items[i];
      assert((left_expr->fixed && item_i->fixed) ||
             (item_i->type() == REF_ITEM &&
              ((Item_ref *)(item_i))->ref_type() == Item_ref::OUTER_REF));
      if (item_i->check_cols(left_expr->element_index(i)->cols())) return true;
      Item_ref *const left =
          new Item_ref(&select->context, (*optimizer->get_cache())->addr(i),
                       in_left_expr_name);
      if (left == nullptr) return true;

      if (mark_as_outer(left_expr, i))
        left->depended_from = select->outer_query_block();

      Item_bool_func *item = new Item_func_eq(
          left, new Item_ref(&select->context, pitem_i, "<list ref>"));
      if (item == nullptr) return true;
      item->set_created_by_in2exists();
      if (!abort_on_null) {
        Item_bool_func *having_col_item = new Item_is_not_null_test(
            this, new Item_ref(&select->context, pitem_i, "<list ref>"));
        if (having_col_item == nullptr) return true;
        having_col_item->set_created_by_in2exists();
        Item_bool_func *item_isnull = new Item_func_isnull(
            new Item_ref(&select->context, pitem_i, "<list ref>"));
        if (item_isnull == nullptr) return true;
        item_isnull->set_created_by_in2exists();
        item = new Item_cond_or(item, item_isnull);
        if (item == nullptr) return true;
        item->set_created_by_in2exists();
        /*
          TODO: why we create the above for cases where the right part
                can't be NULL?
        */
        if (left_expr->element_index(i)->is_nullable()) {
          item = new Item_func_trig_cond(
              item, get_cond_guard(i), nullptr, NO_PLAN_IDX,
              Item_func_trig_cond::OUTER_FIELD_IS_NOT_NULL);
          if (item == nullptr) return true;
          item->set_created_by_in2exists();
          having_col_item = new Item_func_trig_cond(
              having_col_item, get_cond_guard(i), nullptr, NO_PLAN_IDX,
              Item_func_trig_cond::OUTER_FIELD_IS_NOT_NULL);
          if (having_col_item == nullptr) return true;
          having_col_item->set_created_by_in2exists();
        }
        having_item = and_items(having_item, having_col_item);
        if (having_item == nullptr) return true;
        having_item->set_created_by_in2exists();
      }

      where_item = and_items(where_item, item);
      if (where_item == nullptr) return true;
      where_item->set_created_by_in2exists();
    }
    /*
      AND can't be changed during fix_fields()
      we can assign select->where_cond() here, and pass NULL as last
      argument (reference) to fix_fields()
    */
    select->set_where_cond(and_items(select->where_cond(), where_item));
    select->where_cond()->apply_is_true();
    in2exists_info->added_to_where = true;
    Opt_trace_array where_trace(&thd->opt_trace,
                                "evaluating_constant_where_conditions");
    if (select->where_cond()->fix_fields(thd, nullptr)) return true;
  }
  if (having_item != nullptr) {
    select->set_having_cond(and_items(select->having_cond(), having_item));
    select->having_cond()->apply_is_true();
    /*
      AND can't be changed during fix_fields()
      we can assign select->having_cond() here, and pass 0 as last
      argument (reference) to fix_fields()
    */
    select->having_fix_field = true;
    Opt_trace_array having_trace(&thd->opt_trace,
                                 "evaluating_constant_having_conditions");
    if (select->having_cond()->fix_fields(thd, nullptr)) return true;
    select->having_fix_field = false;
  }

  return false;
}

bool Item_in_subselect::select_transformer(THD *thd, Query_block *select) {
  return select_in_like_transformer(thd, select, &eq_creator);
}

/**
  Prepare IN/ALL/ANY/SOME subquery transformation and call appropriate
  transformation function.

    To decide which transformation procedure (scalar or row) applicable here
    we have to call fix_fields() for left expression to be able to call
    cols() method on it. Also this method make arena management for
    underlying transformation methods.

  @param thd     Thread handle
  @param select  Query block of subquery being transformed
  @param func    creator of condition function of subquery

  @returns false if success, true if error
*/

bool Item_in_subselect::select_in_like_transformer(THD *thd,
                                                   Query_block *select,
                                                   Comp_creator *func) {
  const char *save_where = thd->where;

  DBUG_TRACE;

#ifndef NDEBUG
  /*
    IN/SOME/ALL/ANY subqueries don't support LIMIT clause. Without
    it, ORDER BY becomes meaningless and should already have been
    removed in resolve_subquery()
  */
  for (Query_block *sl = unit->first_query_block(); sl;
       sl = sl->next_query_block())
    assert(!sl->order_list.first);
#endif

  if (changed) return false;

  thd->where = "IN/ALL/ANY subquery";

  thd->lex->set_current_query_block(select->outer_query_block());

  assert(left_expr->fixed);
  /*
    In some optimisation cases we will not need this Item_in_optimizer
    object, but we can't know it here, but here we need address correct
    reference on left expression.
  */
  if (optimizer == nullptr) {
    optimizer = new Item_in_optimizer(this);
    if (optimizer == nullptr) return true;
  }

  thd->lex->set_current_query_block(select);

  /*
    If we didn't choose an execution method up to this point, we choose
    the IN=>EXISTS transformation, at least temporarily.
  */
  if (strategy == Subquery_strategy::UNSPECIFIED)
    strategy = Subquery_strategy::CANDIDATE_FOR_IN2EXISTS_OR_MAT;

  /*
    Both transformers call fix_fields() only for Items created inside them,
    and all those items do not make permanent changes in the current item arena
    which allows us to call them with changed arena (if we do not know the
    nature of Item, we have to call fix_fields() for it only with the original
    arena to avoid memory leak).
  */

  if (left_expr->cols() == 1) {
    if (single_value_transformer(thd, select, func)) return true;
  } else {
    // Row operation is only supported for =ANY (IN) and <>ALL (NOT IN):
    if (func != &eq_creator) {
      my_error(ER_OPERAND_COLUMNS, MYF(0), 1);
      return true;
    }
    if (row_value_transformer(thd, select)) return true;
  }

  thd->where = save_where;
  return false;
}

void Item_in_subselect::print(const THD *thd, String *str,
                              enum_query_type query_type) const {
  const char *tail = Item_bool_func::bool_transform_names[value_transform];
  if (implicit_is_op) tail = "";
  bool paren = false;
  if (strategy == Subquery_strategy::CANDIDATE_FOR_IN2EXISTS_OR_MAT ||
      strategy == Subquery_strategy::SUBQ_EXISTS) {
    if (value_transform == BOOL_NEGATED) {  // NOT has low associativity, but
                                            // we're inside Item_in_optimizer,
      // so () are needed only if IS TRUE/FALSE is coming.
      if (tail[0]) {
        paren = true;
        str->append(STRING_WITH_LEN("("));
      }
      str->append(STRING_WITH_LEN("not "));
    }
    str->append(STRING_WITH_LEN("<exists>"));
  } else {
    left_expr->print(thd, str, query_type);
    if (value_transform == BOOL_NEGATED) str->append(STRING_WITH_LEN(" not"));
    str->append(STRING_WITH_LEN(" in "));
  }
  Item_subselect::print(thd, str, query_type);
  if (paren) str->append(STRING_WITH_LEN(")"));
  if (tail[0]) {
    str->append(STRING_WITH_LEN(" "));
    str->append(tail, strlen(tail));
  }
}

/**
  An object of class Item_in_subselect is always substituted with another
  object of class Item_in_optimizer, and the substitution object contains
  a pointer to the original Item_in_subselect.
  This substitution is currently handled by calling fix_fields() twice:
  The first call will resolve the underlying query expression and create
  the Item_in_optimizer substitution object.
  The second call is performed from Item_in_optimizer::fix_fields() and
  will complete the resolving of the object.
  Notice also that this process is partly managed by
  Item_subselect::fix_fields().
*/
bool Item_in_subselect::fix_fields(THD *thd, Item **ref) {
  assert(!fixed);

  abort_on_null =
      value_transform == BOOL_IS_TRUE || value_transform == BOOL_NOT_TRUE;

  thd->where = "IN/ALL/ANY subquery";

  assert(left_expr != nullptr);
  if (!left_expr->fixed) {
    if (left_expr->fix_fields(thd, &left_expr)) {
      return true;
    }
    used_tables_cache = left_expr->used_tables();
  }

  if (Item_subselect::fix_fields(thd, ref)) return true;

  return false;
}

void Item_in_subselect::fix_after_pullout(Query_block *parent_query_block,
                                          Query_block *removed_query_block) {
  Item_subselect::fix_after_pullout(parent_query_block, removed_query_block);
  left_expr->fix_after_pullout(parent_query_block, removed_query_block);
  used_tables_cache |= left_expr->used_tables();
}

void Item_in_subselect::update_used_tables() {
  Item_subselect::update_used_tables();
  left_expr->update_used_tables();
  used_tables_cache |= left_expr->used_tables();
  add_accum_properties(left_expr);
}

/**
  Initialize the cache of the left operand of the IN predicate.

  @note This method has the same purpose as alloc_group_fields(),
  but it takes a different kind of collection of items, and the
  list we push to is dynamically allocated.

  @retval true  if a memory allocation error occurred
  @retval false if success
*/

bool Item_in_subselect::init_left_expr_cache(THD *thd) {
  /*
    Check if the left operand is a subquery that yields an empty set of rows.
    If so, skip initializing a cache; for an empty set the subquery
    exec won't read any rows and so lead to uninitialized reads if attempted.
  */
  if (left_expr->type() == SUBSELECT_ITEM && left_expr->null_value) {
    return false;
  }

  JOIN *outer_join = unit->outer_query_block()->join;
  /*
    An IN predicate might be evaluated in a query for which all tables have
    been optimized away.
  */
  if (!(outer_join && outer_join->qep_tab)) {
    need_expr_cache = false;
    return false;
  }

  if (!(left_expr_cache = new (thd->mem_root) List<Cached_item>)) return true;

  for (uint i = 0; i < left_expr->cols(); i++) {
    Cached_item *cur_item_cache =
        new_Cached_item(thd, left_expr->element_index(i));
    if (!cur_item_cache || left_expr_cache->push_front(cur_item_cache))
      return true;
  }
  return false;
}

std::optional<ContainedSubquery> Item_in_subselect::get_contained_subquery(
    const Query_block *outer_query_block) {
  // TODO(sgunders): Respect subquery hints, which can force the
  // strategy to be materialize.
  Query_block *query_block = unit->first_query_block();
  AccessPath *path = unit->root_access_path();
  if (path == nullptr) {
    // In rare situations involving IN subqueries on the left side of
    // other IN subqueries, the query block may not be part of the
    // parent query block's list of inner query blocks. If so, it has
    // not been optimized here. Since this is a rare case, we'll just
    // skip it and assign it zero cost.
    return std::nullopt;
  }

  const bool materializable =
      subquery_allows_materialization(current_thd, query_block,
                                      outer_query_block) &&
      query_block->subquery_strategy(current_thd) ==
          Subquery_strategy::CANDIDATE_FOR_IN2EXISTS_OR_MAT;

  int row_width = 0;
  for (const Item *qb_item : query_block->fields) {
    row_width += std::min<size_t>(qb_item->max_length, kMaxItemLengthEstimate);
  }
  return ContainedSubquery(
      {path,
       materializable ? ContainedSubquery::Strategy::kMaterializable
                      : ContainedSubquery::Strategy::kNonMaterializable,
       row_width});
}

bool IsItemInSubSelect(Item *item) {
  if (item->type() != Item::SUBSELECT_ITEM) {
    return false;
  }
  switch (down_cast<Item_subselect *>(item)->substype()) {
    case Item_subselect::IN_SUBS:
    case Item_subselect::ALL_SUBS:
    case Item_subselect::ANY_SUBS:
      return true;
    default:
      return false;
  }
}

/**
  Tells an Item that it is in the condition of a JOIN_TAB of a query block.

  @param arg  A std::pair: first argument is the query block, second is the
  index of JOIN_TAB in JOIN's array.

  The Item records this fact and can deduce from it the estimated number of
  times that it will be evaluated.
  If the JOIN_TAB doesn't belong to the query block owning this
  Item_subselect, it must belong to a more inner query block (not a more
  outer, as the walk() doesn't dive into subqueries); in that case, it must be
  that Item_subselect is the left-hand-side of a subquery transformed with
  IN-to-EXISTS and has been wrapped in Item_cache and then injected into the
  WHERE/HAVING of that subquery; but then the Item_subselect will not be
  evaluated when the JOIN_TAB's condition is evaluated (Item_cache will
  short-circuit it); it will be evaluated when the IN(subquery)
  (Item_in_optimizer) is - that's when the Item_cache is updated. Thus, we
  will ignore JOIN_TAB in this case.
*/
bool Item_subselect::inform_item_in_cond_of_tab(uchar *arg) {
  std::pair<Query_block *, int> *pair_object =
      pointer_cast<std::pair<Query_block *, int> *>(arg);
  if (pair_object->first == unit->outer_query_block())
    in_cond_of_tab = pair_object->second;
  return false;
}

/**
  Mark the subquery as optimized away, for EXPLAIN.
*/

bool Item_subselect::subq_opt_away_processor(uchar *) {
  unit->set_explain_marker(current_thd, CTX_OPTIMIZED_AWAY_SUBQUERY);
  // Return false to continue marking all subqueries in the expression.
  return false;
}

/**
   Clean up after removing the subquery from the item tree.

   Call Query_expression::exclude_tree() to unlink it from its
   master and to unlink direct Query_block children from
   all_query_blocks_list.

   Don't unlink subqueries that are not descendants of the starting
   point (root) of the removal and cleanup.
 */
bool Item_subselect::clean_up_after_removal(uchar *arg) {
  Cleanup_after_removal_context *const ctx =
      pointer_cast<Cleanup_after_removal_context *>(arg);

  // Check whether this item should be removed
  if (ctx->is_stopped(this)) return false;

  if (reference_count() > 1) {
    (void)decrement_ref_count();
    ctx->stop_at(this);
    return false;
  }

  // Remove item on upward traversal, not downward:
  if (marker == MARKER_NONE) {
    marker = MARKER_TRAVERSAL;
    return false;
  }
  assert(marker == MARKER_TRAVERSAL);
  marker = MARKER_NONE;

  // There may be loops in the AST so make sure a part is not removed twice:
  if (unit->outer_query_block() == nullptr) return false;

  // Notify flatten_subqueries() that subquery has been removed.
  notify_removal();

  // Remove the underlying query expression
  unit->exclude_tree();

  return false;
}

bool Item_subselect::collect_subqueries(uchar *arg) {
  Collect_subq_info *info = pointer_cast<Collect_subq_info *>(arg);
  if (unit->outer_query_block() == info->m_query_block)
    info->list.push_back(this);
  return false;
}

bool Item_allany_subselect::select_transformer(THD *thd, Query_block *select) {
  DBUG_TRACE;
  if (upper_item) upper_item->show = true;
  return select_in_like_transformer(thd, select, func);
}

bool Item_subselect::is_evaluated() const { return unit->is_executed(); }

void Item_allany_subselect::print(const THD *thd, String *str,
                                  enum_query_type query_type) const {
  if (strategy == Subquery_strategy::CANDIDATE_FOR_IN2EXISTS_OR_MAT ||
      strategy == Subquery_strategy::SUBQ_EXISTS)
    str->append(STRING_WITH_LEN("<exists>"));
  else {
    left_expr->print(thd, str, query_type);
    str->append(' ');
    str->append(func->symbol(all));
    str->append(all ? " all " : " any ", 5);
  }
  Item_subselect::print(thd, str, query_type);
}

bool Item_singlerow_subselect::collect_scalar_subqueries(uchar *arg) {
  auto *info = pointer_cast<Collect_scalar_subquery_info *>(arg);
  Item *i = unit->first_query_block()->single_visible_field();

  // Skip transformations for row subqueries:
  if (i == nullptr) return false;

  if (!info->m_collect_unconditionally) {
    // Skip transformation if column contains a non-deterministic function [2]
    // Also exclude scalar subqueries with references to outer query blocks [1]
    // and Item_maxmin_subselect (ALL/ANY -> MAX/MIN transform artifact) [3]
    // Merely correlation to the current query block are ok
    if (info->is_stopped(this) || is_outer_reference() ||  // [1]
        is_non_deterministic() ||                          // [2]
        is_maxmin()) {                                     // [3]
      return false;
    }
  }

  /*
    Check if it has been already added. Can happen after other
    transformations, eg. IN -> EXISTS and when aggregates are repeated in
    HAVING clause:
      SELECT SUM(a), (SELECT SUM(b) FROM t3) AS scalar
      FROM t1 HAVING SUM(a) > scalar
   */
  for (auto &e : info->m_list) {
    if (e.item == this) {
      e.m_location |= info->m_location;
      return false;
    }
  }
  const table_map correlated_map = used_tables() & ~PSEUDO_TABLE_BITS;
  info->m_list.emplace_back(Css_info{
      info->m_location, this, correlated_map, info->m_join_condition_context,
      /*
        Compute if we can skip run-time cardinality check:
        [1]   implicitly grouped queries for now, OR
        [1.1] was implicitly grouped in a transformation on a deeper level, AND
        [2]   no set operations are present (union)
      */
      ((i->has_aggregation() &&
        unit->first_query_block()->is_implicitly_grouped()) ||    // [1]
       (unit->first_query_block()->m_was_implicitly_grouped)) &&  // [1.1]
          !unit->is_set_operation(),                              // [2]
      false});
  return false;
}

/**
  Find the scalar subquery in Query_block::fields if directly present,
  i.e., not inside an expression.

  @param select The query block owning the transformation.
  @param subquery The scalar subquery to look for.
  @return the corresponding ref in Query_block::base_ref_items, or nullptr if
    not found.
*/
static Item **find_subquery_in_select_list(Query_block *select,
                                           Item_singlerow_subselect *subquery) {
  int item_idx = 0;
  for (Item *item : select->visible_fields()) {
    // All comparisons are done after unwrapping rollup group item.
    // base_ref_items might be without rollup wrappers while the fields
    // might be.
    item = unwrap_rollup_group(item);
    if (item == subquery) {
      assert(select->base_ref_items[item_idx] == item);
      return &select->base_ref_items[item_idx];
    }
    ++item_idx;
  }
  return nullptr;
}

Item *Item_singlerow_subselect::replace_scalar_subquery(uchar *arg) {
  auto *const info = pointer_cast<Scalar_subquery_replacement *>(arg);
  if (info->m_target != this) return this;

  auto *const scalar_item =
      new (current_thd->mem_root) Item_field(info->m_field);
  if (scalar_item == nullptr) return nullptr;

  Item **ref = find_subquery_in_select_list(info->m_outer_query_block, this);

  if (ref == nullptr) {
    // This scalar subquery is not used directly in the select list, so we need
    // to add it as a hidden field. (If it _is_ used directly in the list,
    // we cannot add it; not only due to efficiency, but it would also cause
    // a conflict in the value of item->hidden.)
    ref = info->m_outer_query_block->add_hidden_item(scalar_item);
  }
  Item *result;
  if (unit->place() == CTX_HAVING) {
    result = new (current_thd->mem_root)
        Item_ref(&info->m_outer_query_block->context, ref, scalar_item->db_name,
                 scalar_item->table_name, scalar_item->field_name);
    // nullptr is error, but no separate return needed here
  } else {
    result = scalar_item;
  }

  if (info->m_add_coalesce) {
    Item_int *zero = new (current_thd->mem_root) Item_int_0();
    if (zero == nullptr) return nullptr;
    Item *coa = new (current_thd->mem_root) Item_func_coalesce(result, zero);
    if (coa == nullptr) return nullptr;
    if (coa->fix_fields(current_thd, &coa)) return nullptr;
    result = coa;
  }
  return result;
}

std::optional<ContainedSubquery>
Item_singlerow_subselect::get_contained_subquery(
    const Query_block *outer_query_block [[maybe_unused]]) {
  if (unit->root_access_path() == nullptr) {
    // In rare situations involving IN subqueries on the left side of
    // other IN subqueries, the query block may not be part of the
    // parent query block's list of inner query blocks. If so, it has
    // not been optimized here. Since this is a rare case, we'll just
    // skip it and assign it zero cost.
    return std::nullopt;
  }

  const ContainedSubquery::Strategy strategy =
      unit->first_query_block()->is_cacheable()
          ? ContainedSubquery::Strategy::kIndependentSingleRow
          : ContainedSubquery::Strategy::kNonMaterializable;

  int row_width = 0;
  for (const Item *qb_item : unit->first_query_block()->fields) {
    row_width += std::min<size_t>(qb_item->max_length, kMaxItemLengthEstimate);
  }

  return ContainedSubquery({unit->root_access_path(), strategy, row_width});
}

Item *Item_subselect::replace_item(Item_transformer t, uchar *arg) {
  auto replace_and_update = [arg, t](Item *expr, Item **ref) {
    Item *new_expr = expr->transform(t, arg);
    if (new_expr == nullptr) return true;
    if (new_expr != expr) current_thd->change_item_tree(ref, new_expr);
    new_expr->update_used_tables();
    return false;
  };

  auto *info = pointer_cast<Item::Item_replacement *>(arg);
  auto *old_current = info->m_curr_block;
  for (Query_block *slave = unit->first_query_block(); slave != nullptr;
       slave = slave->next_query_block()) {
    info->m_curr_block = slave;

    for (auto it = slave->fields.begin(); it != slave->fields.end(); ++it) {
      Item *expr = *it;
      if (replace_and_update(expr, &expr)) return nullptr;
      *it = expr;
    }
    if (slave->where_cond() != nullptr &&
        replace_and_update(slave->where_cond(), slave->where_cond_ref()))
      return nullptr;

    for (ORDER *ord = slave->group_list.first; ord != nullptr;
         ord = ord->next) {
      if (replace_and_update(*ord->item, ord->item)) return nullptr;
    }
    if (slave->having_cond() != nullptr &&
        replace_and_update(slave->having_cond(), slave->having_cond_ref()))
      return nullptr;

    for (ORDER *ord = slave->order_list.first; ord != nullptr;
         ord = ord->next) {
      if (replace_and_update(*ord->item, ord->item)) return nullptr;
    }
    List_iterator<Window> wit(slave->m_windows);
    Window *w;
    while ((w = wit++)) {
      for (auto itr : {w->first_order_by(), w->first_partition_by()}) {
        if (itr != nullptr) {
          for (ORDER *ord = itr; ord != nullptr; ord = ord->next) {
            if (replace_and_update(*ord->item, ord->item)) return nullptr;
          }
        }
      }
    }
  }

  info->m_curr_block = old_current;
  return this;
}

/**
  Transform processor. Dives into a subquery's expressions.
  See Item[_field]::replace_item_field for more details.
*/
Item *Item_subselect::replace_item_field(uchar *arg) {
  return replace_item(&Item::replace_item_field, arg);
}

/**
  Transform processor. Dives into a subquery's expressions.
  See Item[_field]::replace_item_view_ref for more details.
*/
Item *Item_subselect::replace_item_view_ref(uchar *arg) {
  return replace_item(&Item::replace_item_view_ref, arg);
}

void SubqueryWithResult::cleanup() {
  DBUG_TRACE;
  result->cleanup();
}

SubqueryWithResult::SubqueryWithResult(Query_expression *u,
                                       Query_result_interceptor *res,
                                       Item_subselect *si)
    : result(res),
      item(si),
      res_type(STRING_RESULT),
      res_field_type(MYSQL_TYPE_VAR_STRING),
      maybe_null(false),
      unit(u) {
  unit->item = si;
}

/**
  Prepare the query expression underlying the subquery.

  @details
  This function is called from Item_subselect::fix_fields. If the subquery is
  transformed with an Item_in_optimizer object, this function may be called
  twice, hence we need the check on 'is_prepared()' at the start, to avoid
  redoing the preparation.

  @returns false if success, true if error
*/

bool SubqueryWithResult::prepare(THD *thd) {
  if (!unit->is_prepared())
    return unit->prepare(thd, result, nullptr, SELECT_NO_UNLOCK, 0);

  assert(result == unit->query_result());

  return false;
}

/**
  Makes storage for the output values for a scalar or row subquery and
  calculates their data and column types and their nullability.

  @param item_list       list of items in the select list of the subquery
  @param row             cache objects to hold the result row of the subquery
  @param possibly_empty  true if the subquery could return empty result
*/
void SubqueryWithResult::set_row(const mem_root_deque<Item *> &item_list,
                                 Item_cache **row, bool possibly_empty) {
  /*
    Empty scalar or row subqueries evaluate to NULL, so if it is
    possibly empty, it is also possibly NULL.
  */
  maybe_null = possibly_empty;

  res_type = STRING_RESULT;
  res_field_type = MYSQL_TYPE_VARCHAR;
  uint i = 0;
  for (Item *sel_item : VisibleFields(item_list)) {
    item->max_length = sel_item->max_length;
    res_type = sel_item->result_type();
    res_field_type = sel_item->data_type();
    item->decimals = sel_item->decimals;
    item->unsigned_flag = sel_item->unsigned_flag;
    maybe_null |= sel_item->is_nullable();
    if (!(row[i] = Item_cache::get_cache(sel_item))) return;
    row[i]->setup(sel_item);
    row[i]->store(sel_item);
    row[i]->set_nullable(possibly_empty || sel_item->is_nullable());
    ++i;
  }
  if (CountVisibleFields(item_list) > 1)
    res_type = ROW_RESULT;
  else
    item->set_data_type(res_field_type);
}

/**
  Check if a query block is guaranteed to return one row. We know that
  this is the case if it has no tables and is not filtered with WHERE,
  HAVING or LIMIT clauses.

  @param query_block  the Query_block of the query block to check

  @return true if we are certain that the query block always returns
  one row, false otherwise
*/
static bool guaranteed_one_row(const Query_block *query_block) {
  return !query_block->has_tables() && query_block->where_cond() == nullptr &&
         query_block->having_cond() == nullptr && !query_block->has_limit();
}

static bool wrapped_in_intersect_except(Query_term *qb) {
  for (qb = qb->parent(); qb != nullptr; qb = qb->parent()) {
    if (qb->term_type() == QT_EXCEPT || qb->term_type() == QT_INTERSECT)
      return true;
  }
  return false;
}

void SubqueryWithResult::fix_length_and_dec(Item_cache **row) {
  assert(row || unit->first_query_block()->single_visible_field() != nullptr);

  // A UNION is possibly empty only if all of its SELECTs are possibly empty.
  // Other set operations may always be empty
  bool possibly_empty = true;
  for (Query_block *sl = unit->first_query_block(); sl;
       sl = sl->next_query_block()) {
    if (guaranteed_one_row(sl) && !wrapped_in_intersect_except(sl)) {
      possibly_empty = false;
      break;
    }
  }

  set_row(unit->query_term()->query_block()->fields, row, possibly_empty);

  if (unit->first_query_block()->single_visible_field() != nullptr)
    item->collation.set(row[0]->collation);
}

bool SubqueryWithResult::exec(THD *thd) {
  assert(unit->is_optimized());
  char const *save_where = thd->where;
  const bool res = unit->execute(thd);
  thd->where = save_where;
  return res;
}

/**
  Run a query to see if it returns at least one row (stops after the first
  has been found, or on error). Unless there was an error, whether the row
  was found in "found".

  @retval true on error
 */
bool ExecuteExistsQuery(THD *thd, Query_expression *unit, RowIterator *iterator,
                        bool *found) {
  Query_block *saved_query_block = thd->lex->current_query_block();
  auto restore_query_block = create_scope_guard([thd, saved_query_block]() {
    thd->lex->set_current_query_block(saved_query_block);
  });

  Opt_trace_context *const trace = &thd->opt_trace;
  Opt_trace_object trace_wrapper(trace);
  Opt_trace_object trace_exec(trace, "join_execution");
  if (unit->is_simple()) {
    trace_exec.add_select_number(unit->first_query_block()->select_number);
  }
  Opt_trace_array trace_steps(trace, "steps");

  if (unit->ClearForExecution()) {
    return true;
  }

  unit->set_executed();
  thd->get_stmt_da()->reset_current_row_for_condition();
  if (iterator->Init()) {
    return true;
  }

  // See if we can get at least one row.
  int error = iterator->Read();
  if (error == 1 || thd->is_error()) {
    return true;
  }

  *found = (error == 0);
  return false;
}

/*
  Index-lookup subselect 'engine' - run the subquery

  DESCRIPTION
    The engine is used to resolve subqueries in form

      oe IN (SELECT key FROM tbl WHERE subq_where)

    by asking the iterator for the inner query for a single row, and then
    immediately stopping. The iterator would usually do a simple ref lookup,
    but could in theory be anything.
*/

bool subselect_indexsubquery_engine::exec(THD *thd) {
  Query_expression *unit = item->unit;
  bool found;
  if (ExecuteExistsQuery(thd, unit, unit->root_iterator(), &found)) {
    return true;
  }
  item->value = found;
  item->assigned(true);
  return false;
}

uint Item_subselect::unit_cols() const {
  assert(unit->is_prepared());  // should be called after fix_fields()
  return unit->num_visible_fields();
}

bool Item_subselect::is_uncacheable() const { return unit->uncacheable; }

void SubqueryWithResult::print(const THD *thd, String *str,
                               enum_query_type query_type) {
  unit->print(thd, str, query_type);
}

void subselect_indexsubquery_engine::print(const THD *thd, String *str,
                                           enum_query_type query_type) {
  const bool unique = type == JT_EQ_REF;
  const bool check_null = type == JT_REF_OR_NULL;

  if (unique)
    str->append(STRING_WITH_LEN("<primary_index_lookup>("));
  else
    str->append(STRING_WITH_LEN("<index_lookup>("));
  ref.items[0]->print(thd, str, query_type);
  str->append(STRING_WITH_LEN(" in "));
  if (table_ref && table_ref->uses_materialization()) {
    /*
      For materialized derived tables/views use table/view alias instead of
      temporary table name, as it changes on each run and not acceptable for
      EXPLAIN EXTENDED.
    */
    str->append(table->alias, strlen(table->alias));
  } else if (table->s->table_category == TABLE_CATEGORY_TEMPORARY) {
    // Could be from subselect_hash_sj_engine.
    str->append(STRING_WITH_LEN("<temporary table>"));
  } else
    str->append(table->s->table_name.str, table->s->table_name.length);
  KEY *key_info = table->key_info + ref.key;
  str->append(STRING_WITH_LEN(" on "));
  str->append(key_info->name);
  if (check_null) str->append(STRING_WITH_LEN(" checking NULL"));
  if (cond) {
    str->append(STRING_WITH_LEN(" where "));
    cond->print(thd, str, query_type);
  }
  if (having) {
    str->append(STRING_WITH_LEN(" having "));
    having->print(thd, str, query_type);
  }
  str->append(')');
}

/**
  change query result object of subquery.

  @param thd    thread handle
  @param si		new subselect Item
  @param res		new Query_result object

  @retval
    false OK
  @retval
    true  error
*/

bool SubqueryWithResult::change_query_result(THD *thd, Item_subselect *si,
                                             Query_result_subquery *res) {
  item = si;
  int rc = unit->change_query_result(thd, res, result);
  result = res;
  return rc;
}

Query_block *SubqueryWithResult::single_query_block() const {
  assert(unit->is_simple());
  return unit->first_query_block();
}

/******************************************************************************
  WL#1110 - Implementation of class subselect_hash_sj_engine
******************************************************************************/

/**
  Create all structures needed for subquery execution using hash semijoin.

  @details
  - Create a temporary table to store the result of the IN subquery. The
    temporary table has one hash index on all its columns. If single-column,
    the index allows at most one NULL row.
  - Create a new result sink that sends the result stream of the subquery to
    the temporary table,
  - Create and initialize Index_lookup objects to perform lookups into
    the indexed temporary table.

  @param thd          thread handle
  @param tmp_columns  columns of temporary table

  @note
    Currently Item_subselect::init() already chooses and creates at parse
    time an engine with a corresponding JOIN to execute the subquery.

  @retval true  if error
  @retval false otherwise
*/

bool subselect_hash_sj_engine::setup(
    THD *thd, const mem_root_deque<Item *> &tmp_columns) {
  /* The result sink where we will materialize the subquery result. */
  Query_result_union *tmp_result_sink;
  /* The table into which the subquery is materialized. */
  TABLE *tmp_table;
  KEY *tmp_key;       /* The only index on the temporary table. */
  uint tmp_key_parts; /* Number of keyparts in tmp_key. */
  uint key_length;

  DBUG_TRACE;

  DBUG_EXECUTE_IF("hash_semijoin_fail_in_setup", {
    my_error(ER_UNKNOWN_ERROR, MYF(0));
    return true;
  });

  /* 1. Create/initialize materialization related objects. */

  /*
    Create and initialize a select result interceptor that stores the
    result stream in a temporary table. The temporary table itself is
    managed (created/filled/etc) internally by the interceptor.
  */
  if (!(tmp_result_sink = new (thd->mem_root) Query_result_union()))
    return true;
  if (tmp_result_sink->create_result_table(
          thd, tmp_columns,
          true,  // Eliminate duplicates
          thd->variables.option_bits | TMP_TABLE_ALL_COLUMNS,
          "<materialized_subquery>", true, true))
    return true;

  tmp_table = tmp_result_sink->table;
  tmp_key = tmp_table->key_info;
  if (tmp_table->hash_field) {
    tmp_key_parts = CountVisibleFields(tmp_columns);
    key_length = ALIGN_SIZE(tmp_table->s->reclength);
  } else {
    tmp_key_parts = tmp_key->user_defined_key_parts;
    key_length = ALIGN_SIZE(tmp_key->key_length) * 2;
  }

  result = tmp_result_sink;

  /*
    Make sure there is only one index on the temp table.
  */
  assert(CountVisibleFields(tmp_columns) == tmp_table->s->fields ||
         // Unique constraint is used and a hash field was added
         (tmp_table->hash_field &&
          CountVisibleFields(tmp_columns) == tmp_table->s->fields - 1));
  /* 2. Create/initialize execution related objects. */

  /*
    Create and initialize the Index_lookup used by the index lookup iterator
    into the materialized subquery result.
  */

  table = tmp_table;
  ref.key = 0; /* The only temp table index. */
  ref.key_length = tmp_key->key_length;
  type = (tmp_table->key_info[0].flags & HA_NOSAME) ? JT_EQ_REF : JT_REF;
  if (!(ref.key_buff = (uchar *)thd->mem_calloc(key_length)) ||
      !(ref.key_copy =
            (store_key **)thd->alloc((sizeof(store_key *) * tmp_key_parts))) ||
      !(ref.items = (Item **)thd->alloc(sizeof(Item *) * tmp_key_parts)))
    return true;

  if (tmp_table->hash_field) {
    ref.keypart_hash = &hash;
  }

  uchar *cur_ref_buff = ref.key_buff;

  /*
    Create an artificial condition to post-filter those rows matched by index
    lookups that cannot be distinguished by the index lookup procedure, for
    example:
    - because of truncation (if the outer column type's length is bigger than
    the inner column type's, index lookup will use a truncated outer
    value as search key, yielding false positives).
    - because the index is over hash_field and thus not unique.

    Prepared statements execution requires that fix_fields is called
    for every execution. In order to call fix_fields we need to create a
    Name_resolution_context and a corresponding Table_ref for the
    temporary table for the subquery, so that all column references to the
    materialized subquery table can be resolved correctly.
  */
  assert(cond == nullptr);
  if (!(cond = new Item_cond_and)) return true;
  /*
    Table reference for tmp_table that is used to resolve column references
    (Item_fields) to columns in tmp_table.
  */
  Table_ref *tmp_table_ref =
      new (thd->mem_root) Table_ref(tmp_table, "<materialized_subquery>");
  if (tmp_table_ref == nullptr) return true;

  // Assign Table_ref pointer temporarily, while creatung fields:
  tmp_table->pos_in_table_list = tmp_table_ref;
  tmp_table_ref->query_block = unit->first_query_block();

  KEY_PART_INFO *key_parts = tmp_key->key_part;
  for (uint part_no = 0; part_no < tmp_key_parts; part_no++) {
    /* New equi-join condition for the current column. */
    Item_func_eq *eq_cond;
    /* Item for the corresponding field from the materialized temp table. */
    Item_field *right_col_item;
    Field *field = tmp_table->visible_field_ptr()[part_no];
    const bool nullable = field->is_nullable();
    ref.items[part_no] = item->left_expr->element_index(part_no);

    if (!(right_col_item =
              new Item_field(thd, &tmp_table_ref->query_block->context,
                             tmp_table_ref, field)) ||
        !(eq_cond = new Item_func_eq(ref.items[part_no], right_col_item)) ||
        ((Item_cond_and *)cond)->add(eq_cond)) {
      delete cond;
      cond = nullptr;
      return true;
    }

    if (tmp_table->hash_field) {
      ref.key_copy[part_no] = new (thd->mem_root)
          store_key_hash_item(thd, field, cur_ref_buff, nullptr,
                              field->pack_length(), ref.items[part_no], &hash);
    } else {
      ref.key_copy[part_no] = new (thd->mem_root) store_key(
          thd, field,
          /* TODO:
             the NULL byte is taken into account in
             key_parts[part_no].store_length, so instead of
             cur_ref_buff + test(maybe_null), we could
             use that information instead.
           */
          cur_ref_buff + (nullable ? 1 : 0), nullable ? cur_ref_buff : nullptr,
          key_parts[part_no].length, ref.items[part_no]);
    }
    if (nullable &&  // nullable column in tmp table,
                     // and UNKNOWN should not be interpreted as FALSE
        !item->abort_on_null) {
      // It must be the single column, or we wouldn't be here
      assert(tmp_key_parts == 1);
      // Be ready to search for NULL into inner column:
      ref.null_ref_key = cur_ref_buff;
      mat_table_has_nulls = NEX_UNKNOWN;
    } else {
      ref.null_ref_key = nullptr;
      mat_table_has_nulls = NEX_IRRELEVANT_OR_FALSE;
    }

    if (tmp_table->hash_field)
      cur_ref_buff += field->pack_length();
    else
      cur_ref_buff += key_parts[part_no].store_length;
  }
  tmp_table->pos_in_table_list = nullptr;
  ref.key_err = true;
  ref.key_parts = tmp_key_parts;
  table_ref = tmp_table_ref;

  if (cond->fix_fields(thd, &cond)) return true;

  assert(unit->is_prepared());

  return false;
}

void subselect_hash_sj_engine::create_iterators(THD *thd) {
  if (unit->root_access_path() == nullptr) {
    m_root_access_path =
        NewZeroRowsAccessPath(thd, "Not optimized, outer query is empty");
    m_iterator =
        CreateIteratorFromAccessPath(thd, m_root_access_path, /*join=*/nullptr,
                                     /*eligible_for_batch_mode=*/true);
    return;
  }

  // We're only ever reading one row from the iterator, and record[1] isn't
  // properly set up at this point, so we're not using EQRefIterator.
  // (As a microoptimization, we add a LIMIT 1 if there's a filter and the
  // index is unique, so that any filter added doesn't try to read a second row
  // if the condition fails -- there wouldn't be one anyway.)
  //
  // Also, note that we never need to worry about searching for NULLs
  // (which would require the AlternativeIterator); subqueries with
  // JT_REF_OR_NULL are always transformed with IN-to-EXISTS, and thus,
  // their artificial HAVING rejects NULL values.
  assert(type != JT_REF_OR_NULL);
  AccessPath *path = NewRefAccessPath(thd, table, &ref,
                                      /*use_order=*/false, /*reverse=*/false,
                                      /*count_examined_rows=*/false);

  if (type == JT_EQ_REF && (cond != nullptr || having != nullptr)) {
    path = NewLimitOffsetAccessPath(thd, path, /*limit=*/1, /*offset=*/0,
                                    /*count_all_rows=*/false,
                                    /* reject_multiple_rows=*/false,
                                    /*send_records_override=*/nullptr);
  }
  if (cond != nullptr) {
    path = NewFilterAccessPath(thd, path, cond);
  }
  if (having != nullptr) {
    path = NewFilterAccessPath(thd, path, having);
  }

  /*
    This impersonates the materialized table as a derived table. However, there
    are certain aspects of a derived table that are NOT set, such as
    effective_algorithm, so this assignment is incomplete.
    However, it works for the time being (partially because TABLE object's
    pos_in_table_list is nullptr).
  */
  table_ref->set_derived_query_expression(unit);
  if (table_ref->is_table_function()) {
    path = NewMaterializedTableFunctionAccessPath(
        thd, table, table_ref->table_function, path);
  } else {
    path = GetAccessPathForDerivedTable(
        thd, table_ref, table, /*rematerialize=*/false,
        /*invalidators=*/nullptr, /*need_rowid=*/false, path);
  }

  m_root_access_path = path;
  JOIN *join =
      unit->is_set_operation() ? nullptr : unit->first_query_block()->join;
  unit->finalize(thd);
  m_iterator = CreateIteratorFromAccessPath(thd, path, join,
                                            /*eligible_for_batch_mode=*/true);

  // The unit is not supposed to be executed by itself now.
  unit->clear_root_access_path();
}

subselect_hash_sj_engine::~subselect_hash_sj_engine() {
  /* Assure that cleanup has been called for this engine. */
  assert(!table);

  destroy(result);
}

/**
  Cleanup performed after each execution.
*/

void subselect_hash_sj_engine::cleanup() {
  DBUG_TRACE;
  is_materialized = false;
  if (result != nullptr) result->cleanup();  // Resets the temp table as well
  DEBUG_SYNC(current_thd, "before_index_end_in_subselect");
  m_root_access_path = nullptr;
  m_iterator.reset();
  if (table != nullptr) {
    if (table->file->inited)
      table->file->ha_index_end();  // Close the scan over the index
    close_tmp_table(table);
    free_tmp_table(table);
    // Note that tab->qep_cleanup() is not called
    table = nullptr;
  }
  if (unit->is_executed()) unit->reset_executed();
}

static int safe_index_read(TABLE *table, const Index_lookup &ref) {
  int error = table->file->ha_index_read_map(
      table->record[0], ref.key_buff, make_prev_keypart_map(ref.key_parts),
      HA_READ_KEY_EXACT);
  if (error) return report_handler_error(table, error);
  return 0;
}

/**
  Execute a subquery IN predicate via materialization.

  If needed materialize the subquery into a temporary table, then
  compute the predicate via a lookup into this table.

  @retval true  if error
  @retval false otherwise
*/

bool subselect_hash_sj_engine::exec(THD *thd) {
  DBUG_TRACE;

  /*
    Optimize and materialize the subquery during the first execution of
    the subquery predicate.
  */
  if (!is_materialized) {
    thd->lex->set_current_query_block(unit->first_query_block());
    assert(
        unit->first_query_block()->master_query_expression()->is_optimized());

    // Init() triggers materialization.
    // (It also triggers some unneeded setup of the RefIterator, but it is
    // cheap.)
    bool error = m_iterator->Init();
    if (error || thd->is_fatal_error()) return true;

    /*
      TODO:
      - Unlock all subquery tables as we don't need them. To implement this
        we need to add new functionality to JOIN::join_free that can unlock
        all tables in a subquery (and all its subqueries).
      - The temp table used for grouping in the subquery can be freed
        immediately after materialization (yet it's done together with
        unlocking).
     */
    is_materialized = true;

    // See if we have zero rows or not.
    table->file->info(HA_STATUS_VARIABLE);
    if (table->file->ha_table_flags() & HA_STATS_RECORDS_IS_EXACT) {
      has_zero_rows = (table->file->stats.records == 0);
    } else {
      // Index must be closed before starting to scan.
      if (table->file->inited) table->file->ha_index_or_rnd_end();

      TableScanIterator scan(thd, table, /*expected_rows=*/-1.0,
                             /*examined_rows=*/nullptr);
      int ret = scan.Read();
      if (ret == 1 || thd->is_error()) {
        return true;
      }
      has_zero_rows = (ret == -1);
    }
  }  // if (!is_materialized)

  if (has_zero_rows) {
    // The correct answer is FALSE.
    item->value = false;
    return false;
  }
  /*
    Here we could be brutal and set item->null_value. But we prefer to be
    well-behaved and rather set the properties which
    Item_in_subselect::val_bool() and Item_in_optimizer::val_int() expect,
    and then those functions will set null_value based on those properties.
  */
  if (item->left_expr->element_index(0)->null_value) {
    /*
      The first outer expression oe1 is NULL. It is the single outer
      expression because if there would be more ((oe1,oe2,...)IN(...)) then
      either they would be non-nullable (so we wouldn't be here) or the
      predicate would be top-level (so we wouldn't be here,
      Item_in_optimizer::val_int() would have short-cut). The correct answer
      is UNKNOWN. Do as if searching with all triggered conditions disabled:
      this would surely find a row. The caller will translate this to UNKNOWN.
    */
    assert(item->left_expr->cols() == 1);
    item->value = true;
    return false;
  }

  hash = 0;
  bool found;
  if (ExecuteExistsQuery(thd, item->unit, m_iterator.get(), &found)) {
    return true;
  }
  item->value = found;
  item->assigned(true);

  if (!found &&  // no exact match
      mat_table_has_nulls != NEX_IRRELEVANT_OR_FALSE) {
    /*
      There is only one outer expression. It's not NULL. exec() above has set
      the answer to FALSE, but if there exists an inner NULL in the temporary
      table, then the correct answer is UNKNOWN, so let's find out.
    */
    if (mat_table_has_nulls == NEX_UNKNOWN)  // We do not know yet
    {
      // Search for NULL inside tmp table, and remember the outcome.
      *ref.null_ref_key = 1;
      if (!table->file->inited &&
          table->file->ha_index_init(ref.key, false /* sorted */))
        return true;
      if (safe_index_read(table, ref) == 1) return true;
      *ref.null_ref_key = 0;  // prepare for next searches of non-NULL
      mat_table_has_nulls =
          table->has_row() ? NEX_TRUE : NEX_IRRELEVANT_OR_FALSE;
    }
    if (mat_table_has_nulls == NEX_TRUE) {
      /*
        There exists an inner NULL. The correct answer is UNKNOWN.
        Do as if searching with all triggered conditions enabled; that
        would not find any match, but Item_is_not_null_test would notice a
        NULL:
      */
      item->value = false;
      item->was_null = true;
    }
  }
  return false;
}

/**
  Print the state of this engine into a string for debugging and views.
*/

void subselect_hash_sj_engine::print(const THD *thd, String *str,
                                     enum_query_type query_type) {
  str->append(STRING_WITH_LEN(" <materialize> ("));
  unit->print(thd, str, query_type);
  str->append(STRING_WITH_LEN(" ), "));
  if (table)
    subselect_indexsubquery_engine::print(thd, str, query_type);
  else
    str->append(
        STRING_WITH_LEN("<the access method for lookups is not yet created>"));
}
