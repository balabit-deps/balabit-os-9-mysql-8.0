/* Copyright (c) 2011, 2025, Oracle and/or its affiliates.

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

#include <assert.h>
#include <gtest/gtest.h>
#include <stddef.h>

#include <string>

#include "sql/sql_lex.h"
#include "thr_lock.h"
#include "unittest/gunit/parsertest.h"
#include "unittest/gunit/test_utils.h"

namespace union_syntax_unittest {

using my_testing::Mock_error_handler;
using my_testing::Server_initializer;

class UnionSyntaxTest : public ParserTest {
 protected:
  void test_union_syntax(const char *query, int num_terms,
                         bool expect_syntax_error = false) {
    Query_block *term1 = parse(query, expect_syntax_error ? ER_PARSE_ERROR : 0);
    EXPECT_EQ(nullptr, term1->first_inner_query_expression());
    EXPECT_EQ(nullptr, term1->next_select_in_list());
    EXPECT_EQ(1, term1->get_fields_list()->front()->val_int());

    Query_expression *top_union = term1->master_query_expression();
    EXPECT_EQ(nullptr, top_union->outer_query_block());

    if (num_terms > 1) {
      Query_block *term2 = term1->next_query_block();
      ASSERT_FALSE(term2 == nullptr);

      EXPECT_EQ(nullptr, term2->first_inner_query_expression());
      EXPECT_EQ(term1, term2->next_select_in_list());
      EXPECT_EQ(2, term2->get_fields_list()->front()->val_int());

      if (num_terms > 2) {
      } else
        EXPECT_EQ(nullptr, term2->next_query_block());

      EXPECT_EQ(top_union, term2->master_query_expression());
    }
  }

  Query_block *test_ignored_trailing_limit_on_query_term(const char *query) {
    Query_block *term1 = parse(query);

    EXPECT_EQ(nullptr, term1->select_limit);

    Query_expression *top_union = term1->master_query_expression();

    EXPECT_EQ(4,
              top_union->query_term()->query_block()->select_limit->val_int());

    EXPECT_EQ(nullptr, top_union->outer_query_block());

    Query_block *term2 = term1->next_query_block();

    EXPECT_EQ(nullptr, term2->first_inner_query_expression());
    EXPECT_EQ(term1, term2->next_select_in_list());
    EXPECT_EQ(2, term2->get_fields_list()->front()->val_int());

    return term1;
  }

  void test_ignored_trailing_limit_on_query_term(const char *query,
                                                 int expected_limit) {
    Query_block *term1 = test_ignored_trailing_limit_on_query_term(query);
    EXPECT_EQ(expected_limit,
              term1->next_query_block()->select_limit->val_int())
        << " Outer limit clause should be ignored.";
  }
};

TEST_F(UnionSyntaxTest, First) {
  Query_block *top = parse("SELECT 1");
  Query_expression *top_union = top->master_query_expression();

  EXPECT_EQ(nullptr, top->outer_query_block());
  EXPECT_EQ(top, top_union->first_query_block());
}

using std::string;

string parenthesize(string query, int n) {
  string new_query(n, '(');
  new_query += query;
  new_query.append(n, ')');
  return new_query;
}

TEST_F(UnionSyntaxTest, QueryExpParensDualOrder) {
  Query_block *term = parse("( SELECT 1 FROM t1 ORDER BY 2 ) ORDER BY 3");
  ASSERT_FALSE(term == nullptr);
  EXPECT_EQ(nullptr, term->next_query_block());
  EXPECT_EQ(nullptr, term->first_inner_query_expression());

  // The query expression.
  Query_expression *exp = term->master_query_expression();
  ASSERT_FALSE(exp == nullptr);
  EXPECT_EQ(term, exp->first_query_block());

  // Table expression
  EXPECT_EQ(1U, term->m_table_list.elements);
  Table_ref *table_list = term->get_table_list();
  EXPECT_STREQ("t1", table_list->alias);

  // Inner order clause, outer is ignored
  EXPECT_EQ(1U, term->order_list.elements);
  ORDER *inner_order = term->order_list.first;
  Item *order_exp = *inner_order->item;
  EXPECT_EQ(2, order_exp->val_int());
}

TEST_F(UnionSyntaxTest, QueryExpParensOrder) {
  Query_block *term = parse("(SELECT 1 FROM t1) ORDER BY 3");
  ASSERT_FALSE(term == nullptr);
  EXPECT_EQ(nullptr, term->next_query_block());
  EXPECT_EQ(nullptr, term->first_inner_query_expression());

  // The query expression.
  Query_expression *exp = term->master_query_expression();
  ASSERT_FALSE(exp == nullptr);
  EXPECT_EQ(term, exp->first_query_block());

  // Table expression
  EXPECT_EQ(1U, term->m_table_list.elements);
  Table_ref *table_list = term->get_table_list();
  EXPECT_STREQ("t1", table_list->alias);

  // Inner order clause, outer is used when inner is missing
  EXPECT_EQ(1U, term->order_list.elements);
  ORDER *inner_order = term->order_list.first;
  ASSERT_FALSE(inner_order == nullptr);
  Item *order_exp = *inner_order->item;
  EXPECT_EQ(3, order_exp->val_int());
}

TEST_F(UnionSyntaxTest, QueryExpParensLimit1) {
  Query_block *term = parse("(SELECT 1 FROM t1 LIMIT 2) LIMIT 3");
  ASSERT_FALSE(term == nullptr);
  EXPECT_EQ(nullptr, term->next_query_block());
  EXPECT_EQ(nullptr, term->first_inner_query_expression());

  // The query expression.
  Query_expression *exp = term->master_query_expression();
  ASSERT_FALSE(exp == nullptr);
  EXPECT_EQ(term, exp->first_query_block());

  // Table expression
  EXPECT_EQ(1U, term->m_table_list.elements);
  Table_ref *table_list = term->get_table_list();
  EXPECT_STREQ("t1", table_list->alias);

  EXPECT_EQ(2, term->select_limit->val_int())
      << " Smaller limit always override larger value";

  term = parse("(SELECT 1 FROM t1 LIMIT 3) LIMIT 2");
  EXPECT_EQ(2, term->select_limit->val_int())
      << " Smaller limit always override larger value";
}

TEST_F(UnionSyntaxTest, Simple) {
  Query_block *block1 = parse("SELECT 1 UNION SELECT 2 UNION SELECT 3");
  Query_block *block2 = block1->next_query_block();
  Query_block *block3 = block2->next_query_block();

  EXPECT_EQ(1, block1->get_fields_list()->front()->val_int());
  EXPECT_EQ(2, block2->get_fields_list()->front()->val_int());
  EXPECT_EQ(3, block3->get_fields_list()->front()->val_int());
}

TEST_F(UnionSyntaxTest, ThreeWay) {
  const int max_parens = 2;

  for (int top_parens = 0; top_parens <= max_parens; ++top_parens)
    for (int u1parens = 0; u1parens <= max_parens; ++u1parens)
      for (int u2parens = 0; u2parens <= max_parens; ++u2parens)
        for (int u3parens = 0; u3parens <= max_parens; ++u3parens) {
          string query = parenthesize("SELECT 1", u1parens) + " UNION " +
                         parenthesize("SELECT 2", u2parens) + " UNION " +
                         parenthesize("SELECT 3", u3parens);

          query = parenthesize(query, top_parens);
          test_union_syntax(query.c_str(), 3);
        }
}

const char *get_order_by_column_name(Query_block *query_block, int index = 0) {
  EXPECT_EQ(nullptr, *query_block->order_list.next);
  ORDER *current = query_block->order_list.first;
  for (int i = 0; i < index; ++i) current = current->next;
  Item *order_expression = current->item[0];
  EXPECT_EQ(Item::FIELD_ITEM, order_expression->type());
  //  ASSERT_EQ(Item::FIELD_ITEM, order_expression->type());
  assert(Item::FIELD_ITEM == order_expression->type());
  return order_expression->item_name.ptr();
}

const char *get_order_by_column_name(Query_expression *query_expression,
                                     int index = 0) {
  Query_block *top_qb = query_expression->query_term()->query_block();
  // Why can't I use ASSERT_FALSE here?!
  EXPECT_FALSE(top_qb == nullptr);
  return get_order_by_column_name(top_qb, index);
}

int get_limit(Query_block *query_block) {
  return query_block->select_limit->val_int();
}

TEST_F(UnionSyntaxTest, UnionOrderLimit) {
  Query_block *block1 =
      parse("SELECT 1 UNION SELECT 2 FROM t1 ORDER BY a LIMIT 123");
  Query_block *block2 = block1->next_query_block();

  EXPECT_EQ(nullptr, block1->select_limit)
      << "First query block should not have a limit clause.";

  EXPECT_EQ(nullptr, block2->select_limit)
      << "Second query block should not have a limit clause.";

  EXPECT_EQ(0U, block1->order_list.elements)
      << "First query block should not have an order by clause.";

  EXPECT_EQ(0U, block2->order_list.elements)
      << "Second query block should not have an order by clause.";

  Query_expression *query_expression = block1->master_query_expression();

  // The limit and order by clauses should belong to the whole query
  // expression, i.e. the top level post processing query block.
  Query_block *top_qb = query_expression->query_term()->query_block();
  EXPECT_EQ(123, get_limit(top_qb));
  EXPECT_STREQ("a", get_order_by_column_name(top_qb));
}

TEST_F(UnionSyntaxTest, UnionNestedQueryBlock) {
  Query_block *block1 =
      parse("SELECT 1 UNION (SELECT 2 FROM t1 ORDER BY a LIMIT 123)");
  Query_block *block2 = block1->next_query_block();

  EXPECT_EQ(nullptr, block1->select_limit)
      << "First query block should not have a limit clause.";

  EXPECT_EQ(0U, block1->order_list.elements)
      << "First query block should not have an order by clause.";

  EXPECT_EQ(123, get_limit(block2));
  EXPECT_STREQ("a", get_order_by_column_name(block2));

  Query_expression *query_expression = block1->master_query_expression();

  // The limit and order by clauses should not belong to the whole query
  // expression, i.e. the top level post processing query block
  Query_block *top_qb = query_expression->query_term()->query_block();
  EXPECT_EQ(nullptr, top_qb->select_limit)
      << "The union should not have a LIMIT/OFFSET clause.";
  EXPECT_EQ(0U, top_qb->order_list.elements)
      << "The union should not have an order by clause.";
}

TEST_F(UnionSyntaxTest, NestedQueryExpWithLimit) {
  Query_block *block1 =
      parse("(SELECT 1 ORDER BY a LIMIT 5) UNION SELECT 2 ORDER BY b LIMIT 8");

  Query_expression *query_expression = block1->master_query_expression();

  EXPECT_STREQ("a", get_order_by_column_name(block1, 0));
  EXPECT_EQ(5, block1->select_limit->val_int());

  Query_block *fake = query_expression->query_term()->query_block();
  EXPECT_STREQ("b", get_order_by_column_name(fake, 0));
  EXPECT_EQ(8, fake->select_limit->val_int());
}

TEST_F(UnionSyntaxTest, IgnoredTrailingLimitOnQueryTerm) {
  Query_block *block1 = parse("(SELECT 1) UNION SELECT 2 LIMIT 123");
  Query_block *block2 = block1->next_query_block();
  EXPECT_EQ(2, block2->get_fields_list()->front()->val_int());

  // Neither query block should have a limit clause.
  EXPECT_EQ(nullptr, block1->select_limit);
  EXPECT_EQ(nullptr, block2->select_limit);

  Query_expression *query_expression = block1->master_query_expression();

  // The limit clause should belong to the whole query expression, i.e. the
  // "fake select lex".
  EXPECT_EQ(
      123,
      query_expression->query_term()->query_block()->select_limit->val_int());

  return;
  test_ignored_trailing_limit_on_query_term(
      "(SELECT 1) UNION (SELECT 2 LIMIT 3) LIMIT 4", 3);

  test_ignored_trailing_limit_on_query_term(
      "(SELECT 1) UNION ((SELECT 2 LIMIT 3)) LIMIT 4", 3);

  test_ignored_trailing_limit_on_query_term(
      "(SELECT 1) UNION (SELECT 2) LIMIT 4");

  test_ignored_trailing_limit_on_query_term(
      "(SELECT 1) UNION ((SELECT 2)) LIMIT 4");
}

TEST_F(UnionSyntaxTest, InnerVsOuterOrder) {
  Query_block *query_block =
      parse("(SELECT b, a FROM t1 ORDER by b, a LIMIT 3) ORDER by a, b");

  EXPECT_STREQ("b", get_order_by_column_name(query_block, 0));
  EXPECT_STREQ("a", get_order_by_column_name(query_block, 1));
  EXPECT_EQ(3, get_limit(query_block));

  Query_expression *query_expression = query_block->master_query_expression();
  EXPECT_STREQ("a", get_order_by_column_name(query_expression, 0));
  EXPECT_STREQ("b", get_order_by_column_name(query_expression, 1));
  //    EXPECT_EQ(2, get_limit(query_expression->fake_query_block));
}

TEST_F(UnionSyntaxTest, QueryTermIteratorReentrancy) {
  Query_block *query_block = parse(
      "(SELECT * FROM r UNION ALL SELECT * FROM s ORDER BY a LIMIT 10)"
      " UNION ALL "
      " (SELECT * FROM r UNION DISTINCT SELECT * FROM s) LIMIT 7");

  Query_expression *qe = query_block->master_query_expression();
  Query_terms<QTC_POST_ORDER, VL_VISIT_LEAVES> terms(qe->query_term());
  // set of nodes collected without any "interference"
  std::vector<Query_term *> nodes_a_priori;
  std::vector<Query_term *> nodes_outer;
  std::vector<Query_term *> nodes_inner;

  for (Query_term *term1 : terms) {
    nodes_a_priori.push_back(term1);
  }

  EXPECT_EQ(7, nodes_a_priori.size());

  for (Query_term *term1 : terms) {
    // run a second iterator over the same query terms and verify that it
    // doesn't interfere with the outer iterator's job
    for (Query_term *term2 : terms) {
      nodes_inner.push_back(term2);
    }
    EXPECT_EQ(nodes_a_priori, nodes_inner);
    nodes_inner.clear();
    nodes_outer.push_back(term1);
  }
  EXPECT_EQ(nodes_a_priori, nodes_outer);
}

}  // namespace union_syntax_unittest
