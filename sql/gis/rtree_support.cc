// Copyright (c) 2017, 2025, Oracle and/or its affiliates.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License, version 2.0,
// as published by the Free Software Foundation.
//
// This program is designed to work with certain software (including
// but not limited to OpenSSL) that is licensed under separate terms,
// as designated in a particular file or component or in included license
// documentation.  The authors of MySQL hereby grant you an additional
// permission to link the program and your derivative works with the
// separately licensed software that they have either included with
// the program or referenced in the documentation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License, version 2.0, for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA

/// @file
///
/// This file implements the set of functions that storage engines can call to
/// do geometrical operations.

#include "sql/gis/rtree_support.h"

#include <algorithm>  // std::min, std::max
#include <cmath>      // std::isfinite, std::isinf, std::isnan
#include <limits>

#include <boost/geometry.hpp>

#include "my_byteorder.h"  // doubleget, float8get
#include "my_inttypes.h"   // uchar
#include "sql/current_thd.h"
#include "sql/dd/cache/dictionary_client.h"
#include "sql/dd/types/spatial_reference_system.h"
#include "sql/gis/box.h"
#include "sql/gis/box_traits.h"
#include "sql/gis/covered_by_functor.h"
#include "sql/gis/disjoint_functor.h"
#include "sql/gis/equals_functor.h"
#include "sql/gis/geometries.h"
#include "sql/gis/geometries_cs.h"
#include "sql/gis/intersects_functor.h"
#include "sql/gis/mbr_utils.h"
#include "sql/gis/srid.h"
#include "sql/gis/wkb.h"
#include "sql/spatial.h"    // SRID_SIZE
#include "sql/sql_class.h"  // THD
#include "sql/srs_fetcher.h"
#include "template_utils.h"  // pointer_cast

namespace bg = boost::geometry;

dd::Spatial_reference_system *fetch_srs(gis::srid_t srid) {
  const dd::Spatial_reference_system *srs = nullptr;
  dd::cache::Dictionary_client::Auto_releaser m_releaser(
      current_thd->dd_client());
  Srs_fetcher fetcher(current_thd);
  if (srid != 0 && fetcher.acquire(srid, &srs)) return nullptr;

  if (srs)
    return srs->clone();
  else
    return nullptr;
}

bool mbr_contain_cmp(const dd::Spatial_reference_system *srs, rtr_mbr_t *a,
                     rtr_mbr_t *b) {
  assert(a->xmin <= a->xmax && a->ymin <= a->ymax);
  assert(b->xmin <= b->xmax && b->ymin <= b->ymax);

  bool result = false;
  try {
    gis::Covered_by covered_by(srs ? srs->semi_major_axis() : 0.0,
                               srs ? srs->semi_minor_axis() : 0.0);
    if (srs == nullptr || srs->is_cartesian()) {
      gis::Cartesian_box a_box(gis::Cartesian_point(a->xmin, a->ymin),
                               gis::Cartesian_point(a->xmax, a->ymax));
      gis::Cartesian_box b_box(gis::Cartesian_point(b->xmin, b->ymin),
                               gis::Cartesian_point(b->xmax, b->ymax));
      result = covered_by(&b_box, &a_box);
    } else {
      assert(srs->is_geographic());
      gis::Geographic_box a_box(
          gis::Geographic_point(srs->to_radians(a->xmin),
                                srs->to_radians(a->ymin)),
          gis::Geographic_point(srs->to_radians(a->xmax),
                                srs->to_radians(a->ymax)));
      gis::Geographic_box b_box(
          gis::Geographic_point(srs->to_radians(b->xmin),
                                srs->to_radians(b->ymin)),
          gis::Geographic_point(srs->to_radians(b->xmax),
                                srs->to_radians(b->ymax)));
      result = covered_by(&b_box, &a_box);
    }
  } catch (...) {
    assert(false); /* purecov: inspected */
  }

  return result;
}

bool mbr_equal_physically(rtr_mbr_t *a, rtr_mbr_t *b) {
  return a->xmin == b->xmin && a->xmax == b->xmax && a->ymin == b->ymin &&
         a->ymax == b->ymax;
}

bool mbr_equal_logically(const dd::Spatial_reference_system *srs, rtr_mbr_t *a,
                         rtr_mbr_t *b) {
  // These points should not have initialized values at this point,
  // which are min == DBL_MAX and max == -DBL_MAX.
  assert(a->xmin <= a->xmax && a->ymin <= a->ymax);
  assert(b->xmin <= b->xmax && b->ymin <= b->ymax);

  bool result = false;
  try {
    gis::Equals equals(srs ? srs->semi_major_axis() : 0.0,
                       srs ? srs->semi_minor_axis() : 0.0);
    if (srs == nullptr || srs->is_cartesian()) {
      gis::Cartesian_box a_box(gis::Cartesian_point(a->xmin, a->ymin),
                               gis::Cartesian_point(a->xmax, a->ymax));
      gis::Cartesian_box b_box(gis::Cartesian_point(b->xmin, b->ymin),
                               gis::Cartesian_point(b->xmax, b->ymax));
      result = equals(&a_box, &b_box);
    } else {
      assert(srs->is_geographic());
      gis::Geographic_box a_box(
          gis::Geographic_point(srs->to_radians(a->xmin),
                                srs->to_radians(a->ymin)),
          gis::Geographic_point(srs->to_radians(a->xmax),
                                srs->to_radians(a->ymax)));
      gis::Geographic_box b_box(
          gis::Geographic_point(srs->to_radians(b->xmin),
                                srs->to_radians(b->ymin)),
          gis::Geographic_point(srs->to_radians(b->xmax),
                                srs->to_radians(b->ymax)));
      result = equals(&a_box, &b_box);
    }
  } catch (...) {
    assert(false); /* purecov: inspected */
  }

  return result;
}

bool mbr_intersect_cmp(const dd::Spatial_reference_system *srs, rtr_mbr_t *a,
                       rtr_mbr_t *b) {
  try {
    gis::Intersects intersects(srs ? srs->semi_major_axis() : 0.0,
                               srs ? srs->semi_minor_axis() : 0.0);
    if (srs == nullptr || srs->is_cartesian()) {
      gis::Cartesian_box a_box(gis::Cartesian_point(a->xmin, a->ymin),
                               gis::Cartesian_point(a->xmax, a->ymax));
      gis::Cartesian_box b_box(gis::Cartesian_point(b->xmin, b->ymin),
                               gis::Cartesian_point(b->xmax, b->ymax));
      return intersects(&a_box, &b_box);
    } else {
      assert(srs->is_geographic());
      gis::Geographic_box a_box(
          gis::Geographic_point(srs->to_radians(a->xmin),
                                srs->to_radians(a->ymin)),
          gis::Geographic_point(srs->to_radians(a->xmax),
                                srs->to_radians(a->ymax)));
      gis::Geographic_box b_box(
          gis::Geographic_point(srs->to_radians(b->xmin),
                                srs->to_radians(b->ymin)),
          gis::Geographic_point(srs->to_radians(b->xmax),
                                srs->to_radians(b->ymax)));
      return intersects(&a_box, &b_box);
    }
  } catch (...) {
    assert(false); /* purecov: inspected */
  }
  return false; /* purecov: dead code */
}

bool mbr_disjoint_cmp(const dd::Spatial_reference_system *srs, rtr_mbr_t *a,
                      rtr_mbr_t *b) {
  try {
    gis::Disjoint disjoint(srs ? srs->semi_major_axis() : 0.0,
                           srs ? srs->semi_minor_axis() : 0.0);
    if (srs == nullptr || srs->is_cartesian()) {
      gis::Cartesian_box a_box(gis::Cartesian_point(a->xmin, a->ymin),
                               gis::Cartesian_point(a->xmax, a->ymax));
      gis::Cartesian_box b_box(gis::Cartesian_point(b->xmin, b->ymin),
                               gis::Cartesian_point(b->xmax, b->ymax));
      return disjoint(&a_box, &b_box);
    } else {
      assert(srs->is_geographic());
      gis::Geographic_box a_box(
          gis::Geographic_point(srs->to_radians(a->xmin),
                                srs->to_radians(a->ymin)),
          gis::Geographic_point(srs->to_radians(a->xmax),
                                srs->to_radians(a->ymax)));
      gis::Geographic_box b_box(
          gis::Geographic_point(srs->to_radians(b->xmin),
                                srs->to_radians(b->ymin)),
          gis::Geographic_point(srs->to_radians(b->xmax),
                                srs->to_radians(b->ymax)));
      return disjoint(&a_box, &b_box);
    }
  } catch (...) {
    assert(false); /* purecov: inspected */
  }
  return false; /* purecov: dead code */
}

bool mbr_within_cmp(const dd::Spatial_reference_system *srs, rtr_mbr_t *a,
                    rtr_mbr_t *b) {
  /* This function actually computes `a CoveredBy b` relation.
  And mbr_contain_cmp(src,a,b) actually computes `a Covers b`.

  This function could be as simple as return mbr_contain_cmp(src,b,a), if it
  did not have to handle 'legacy_empty_box' defined as

       {x,y}min = DBL_MAX, {x,y}max= -DBL_MAX

  which historically was used to represent MBR(GEOMETRYCOLECTION()). Nowadays,
  MBR(EMPTY GEOMETRYCOLECTION) is computed to, and stored as 'full_range_box':

       {x,y}min = -DBL_MAX, {x,y}max= DBL_MAX

  The situation where a or b (or both!) equal legacy_empty_box might arise
  because of:
    1. Legacy spatial indexes, which might still contain tuples with MBR for
       empty geometry collection encoded in the old way, and passed as `b`
    2. InnoDB sometimes passing a constant representing the MBR of an empty
       geometry collection in this old form as argument `a`.
  The other predicates (like mbr_contain_cmp) do not seem to be ever used in
  such a way, so they don't have this special handling.

  Scenario 1 occurs if spatial index was created back in 5.7, and contains
  tuples representing GEOMETRYCOLLECTION() and was not rebuilt since then.
  As in 5.7 there were no SRIDs and modern optimizer ignores indexes without
  SRID, InnoDB only does "minimal maintenance" of the index by adding/removing
  tuples in it to match those in clustered index. For that, when traversing the
  R-tree it is using mbr_within_cmp(mbr(PK.geo), mbr(non-leaf)). Note, that the
  clustered index geometry column does not store mbr explicitly, instead it is
  computed at run time, using the current code base, so LHS will never use
  legacy_empty_box format in this case, but RHS might.

  Another action permitted for such index is CHECK TABLE, which uses
  mbr_within_cmp(legacy_empty_box,mbr(node)). More on that below.

  Scenario 2 occurs in already mentioned CHECK TABLE, where InnoDB's intent is
  to traverse the whole R-tree. It achieves this by attempting a search for
  records which satisfy mbr_within_cmp(legacy_empty_box,mbr(node)) which
  conceptually makes sense ("empty set is covered by every set").
  Note that using the new format for empty geometry collection i.e. the
  mbr_within_cmp(full_range_box, mbr(node)) would not achieve this goal,
  because most of mbr(nodes) do not contain full range. What is needed is a
  predicate which always evaluates to true, such as
  mbr_contains_cmp(full_range_box, mbr(node)), alas, that would mean that
  mbr_contains_cmp would also have to be able to handle tuples from legacy
  indexes, and we prefer to support this in just one place, here.

  There are also two other places in which InnoDB specifies a=legacy_empty_box,
  both of which try to handle a missing geometry blob. One of them is when
  reporting operation to undo log, and thus probably unreachable. The other is
  handling a rollback interrupted by a crash where it tries to construct search
  tuple to clean up from secondary index. As row_purge_upd_exist_or_extern_func
  removes externally stored fields (such as geometry blob) only after removing
  secondary index records, there should be no such records to remove, and thus
  search for them isn't needed, but refactoring it is difficult, so we just
  need to avoid a crash here by handling it arbitrarily. Original code handled
  it by scanning full R-tree, and so we do that, too. */
  try {
    if (a->xmax < a->xmin || a->ymax < a->ymin) {
      /* This only happens when InnoDB has specified `a` as special constant:*/
      assert(a->xmin == DBL_MAX);
      assert(a->ymin == DBL_MAX);
      assert(a->xmax == -DBL_MAX);
      assert(a->ymax == -DBL_MAX);
      /* ... which was meant to represent empty geometry collection and as such
      should be considered 'covered by' every other MBR. We handle it by
      returning true because there is no guarantee provided that functions used
      below know how to handle an MBR with min < max. */
      return true;
    }

    // Correct the min and max corners to generate proper boxes.
    // The only reason this can happen, is that b is an mbr comming from 5.7
    // spatial index and is legacy_empty_box.
    if (b->xmax < b->xmin || b->ymax < b->ymin) {
      assert(b->xmin == DBL_MAX);
      assert(b->ymin == DBL_MAX);
      assert(b->xmax == -DBL_MAX);
      assert(b->ymax == -DBL_MAX);
    }
    // We handle it by converting b to the modern (8.0+) representation used for
    // empty geometry collection, which is full_range_box.
    // This is a bit wrong as then everything seems to be covered_by b, so we
    // waste time for traversing fragments of tree which do not really cover
    // anything (except empty geometry collection), but this is handled by other
    // functions which do post-filtering.
    // This behaviour was introduced in 8.0 and we keep it for now.
    const double b_xmin = std::min(b->xmin, b->xmax);
    const double b_ymin = std::min(b->ymin, b->ymax);
    const double b_xmax = std::max(b->xmin, b->xmax);
    const double b_ymax = std::max(b->ymin, b->ymax);
    gis::Covered_by covered_by(srs ? srs->semi_major_axis() : 0.0,
                               srs ? srs->semi_minor_axis() : 0.0);
    if (srs == nullptr || srs->is_cartesian()) {
      gis::Cartesian_box a_box(gis::Cartesian_point(a->xmin, a->ymin),
                               gis::Cartesian_point(a->xmax, a->ymax));
      gis::Cartesian_box b_box(gis::Cartesian_point(b_xmin, b_ymin),
                               gis::Cartesian_point(b_xmax, b_ymax));
      return covered_by(&a_box, &b_box);
    } else {
      assert(srs->is_geographic());
      gis::Geographic_box a_box(
          gis::Geographic_point(srs->to_radians(a->xmin),
                                srs->to_radians(a->ymin)),
          gis::Geographic_point(srs->to_radians(a->xmax),
                                srs->to_radians(a->ymax)));
      gis::Geographic_box b_box(gis::Geographic_point(srs->to_radians(b_xmin),
                                                      srs->to_radians(b_ymin)),
                                gis::Geographic_point(srs->to_radians(b_xmax),
                                                      srs->to_radians(b_ymax)));
      return covered_by(&a_box, &b_box);
    }
  } catch (...) {
    assert(false); /* purecov: inspected */
  }

  return false;
}

void mbr_join(const dd::Spatial_reference_system *srs, double *a,
              const double *b, int n_dim [[maybe_unused]]) {
  assert(n_dim == 2);

  try {
    if (srs == nullptr || srs->is_cartesian()) {
      gis::Cartesian_box a_box(gis::Cartesian_point(a[0], a[2]),
                               gis::Cartesian_point(a[1], a[3]));
      gis::Cartesian_box b_box(gis::Cartesian_point(b[0], b[2]),
                               gis::Cartesian_point(b[1], b[3]));
      bg::expand(a_box, b_box);
      a[0] = a_box.min_corner().x();
      a[1] = a_box.max_corner().x();
      a[2] = a_box.min_corner().y();
      a[3] = a_box.max_corner().y();
    } else {
      assert(srs->is_geographic());
      gis::Geographic_box a_box(
          gis::Geographic_point(srs->to_radians(a[0]), srs->to_radians(a[2])),
          gis::Geographic_point(srs->to_radians(a[1]), srs->to_radians(a[3])));
      gis::Geographic_box b_box(
          gis::Geographic_point(srs->to_radians(b[0]), srs->to_radians(b[2])),
          gis::Geographic_point(srs->to_radians(b[1]), srs->to_radians(b[3])));
      bg::expand(a_box, b_box);
      a[0] = srs->from_radians(a_box.min_corner().x());
      a[1] = srs->from_radians(a_box.max_corner().x());
      a[2] = srs->from_radians(a_box.min_corner().y());
      a[3] = srs->from_radians(a_box.max_corner().y());
    }
  } catch (...) {
    assert(false); /* purecov: inspected */
  }
}

double mbr_join_area(const dd::Spatial_reference_system *srs, const double *a,
                     const double *b, int n_dim [[maybe_unused]]) {
  assert(n_dim == 2);

  double area = 0.0;
  try {
    if (srs == nullptr || srs->is_cartesian()) {
      gis::Cartesian_box a_box(gis::Cartesian_point(a[0], a[2]),
                               gis::Cartesian_point(a[1], a[3]));
      gis::Cartesian_box b_box(gis::Cartesian_point(b[0], b[2]),
                               gis::Cartesian_point(b[1], b[3]));
      bg::expand(a_box, b_box);
      area = bg::area(a_box);
    } else {
      assert(srs->is_geographic());
      gis::Geographic_box a_box(
          gis::Geographic_point(srs->to_radians(a[0]), srs->to_radians(a[2])),
          gis::Geographic_point(srs->to_radians(a[1]), srs->to_radians(a[3])));
      gis::Geographic_box b_box(
          gis::Geographic_point(srs->to_radians(b[0]), srs->to_radians(b[2])),
          gis::Geographic_point(srs->to_radians(b[1]), srs->to_radians(b[3])));
      bg::strategies::geographic<> strategies(bg::srs::spheroid<double>(
          srs->semi_major_axis(), srs->semi_minor_axis()));
      bg::expand(a_box, b_box, strategies);
      area = bg::area(a_box, strategies);
    }
  } catch (...) {
    assert(false); /* purecov: inspected */
  }

  if (!std::isfinite(area)) area = std::numeric_limits<double>::max();
  return area;
}

double compute_area(const dd::Spatial_reference_system *srs, const double *a,
                    int n_dim [[maybe_unused]]) {
  assert(n_dim == 2);

  double area = 0.0;
  try {
    if (srs == nullptr || srs->is_cartesian()) {
      gis::Cartesian_box a_box(gis::Cartesian_point(a[0], a[2]),
                               gis::Cartesian_point(a[1], a[3]));
      area = bg::area(a_box);
    } else {
      assert(srs->is_geographic());
      gis::Geographic_box a_box(
          gis::Geographic_point(srs->to_radians(a[0]), srs->to_radians(a[2])),
          gis::Geographic_point(srs->to_radians(a[1]), srs->to_radians(a[3])));
      bg::strategies::area::geographic<> strategies(bg::srs::spheroid<double>(
          srs->semi_major_axis(), srs->semi_minor_axis()));
      area = bg::area(a_box, strategies);
    }
  } catch (...) {
    assert(false); /* purecov: inspected */
  }

  return area;
}

int get_mbr_from_store(const dd::Spatial_reference_system *srs,
                       const uchar *store, uint size,
                       uint n_dims [[maybe_unused]], double *mbr,
                       gis::srid_t *srid) {
  assert(n_dims == 2);
  // The SRS should match the SRID of the geometry, with one exception: For
  // backwards compatibility it is allowed to create indexes with mixed
  // SRIDs. Although these indexes can never be used to optimize queries, the
  // user is allowed to create them. These indexes will call get_mbr_from_store
  // with srs == nullptr. There is, unfortunately, no way to differentiate mixed
  // SRID indexes from SRID 0 indexes here, so the assertion is not perfect.
  assert(srs == nullptr || (srs->id() == uint4korr(store)));

  if (srid != nullptr) *srid = uint4korr(store);

  try {
    // Note: current_thd may be nullptr here if this function was called from an
    // internal InnoDB thread. In that case, we won't get any stack size check
    // in gis::parse_wkb, but the geometry has been parsed before with the stack
    // size check enabled. We assume we have at least the same amount of stack
    // when called from an internal thread as when called from a MySQL thread.
    std::unique_ptr<gis::Geometry> g =
        gis::parse_wkb(current_thd, srs,
                       pointer_cast<const char *>(store) + sizeof(gis::srid_t),
                       size - sizeof(gis::srid_t), true);
    if (g.get() == nullptr) {
      return -1; /* purecov: inspected */
    }
    if (srs == nullptr || srs->is_cartesian()) {
      gis::Cartesian_box box;
      gis::box_envelope(g.get(), srs, &box);
      mbr[0] = box.min_corner().x();
      mbr[1] = box.max_corner().x();
      mbr[2] = box.min_corner().y();
      mbr[3] = box.max_corner().y();
    } else {
      assert(srs->is_geographic());
      gis::Geographic_box box;
      gis::box_envelope(g.get(), srs, &box);
      mbr[0] = srs->from_radians(box.min_corner().x());
      mbr[1] = srs->from_radians(box.max_corner().x());
      mbr[2] = srs->from_radians(box.min_corner().y());
      mbr[3] = srs->from_radians(box.max_corner().y());
    }
  } catch (...) {
    assert(false); /* purecov: inspected */
    return -1;
  }

  if (std::isnan(mbr[0])) {
    /* purecov: begin inspected */
    assert(std::isnan(mbr[1]) && std::isnan(mbr[2]) && std::isnan(mbr[3]));
    // The geometry is empty, so there is no bounding box. Return a box that
    // covers the entire domain.
    mbr[0] = std::numeric_limits<double>::lowest();
    mbr[1] = std::numeric_limits<double>::max();
    mbr[2] = std::numeric_limits<double>::lowest();
    mbr[3] = std::numeric_limits<double>::max();
    /* purecov: end inspected */
  }

  // xmin <= xmax && ymin <= ymax
  assert(mbr[0] <= mbr[1] && mbr[2] <= mbr[3]);

  return 0;
}

double rtree_area_increase(const dd::Spatial_reference_system *srs,
                           const uchar *mbr_a, const uchar *mbr_b,
                           int mbr_len [[maybe_unused]], double *ab_area) {
  assert(mbr_len == sizeof(double) * 4);

  double a_xmin = float8get(mbr_a);
  double a_xmax = float8get(mbr_a + sizeof(double));
  double a_ymin = float8get(mbr_a + sizeof(double) * 2);
  double a_ymax = float8get(mbr_a + sizeof(double) * 3);
  double b_xmin = float8get(mbr_b);
  double b_xmax = float8get(mbr_b + sizeof(double));
  double b_ymin = float8get(mbr_b + sizeof(double) * 2);
  double b_ymax = float8get(mbr_b + sizeof(double) * 3);

  assert(a_xmin <= a_xmax && a_ymin <= a_ymax);
  assert(b_xmin <= b_xmax && b_ymin <= b_ymax);

  double a_area = 0.0;
  try {
    if (srs == nullptr || srs->is_cartesian()) {
      gis::Cartesian_box a_box(gis::Cartesian_point(a_xmin, a_ymin),
                               gis::Cartesian_point(a_xmax, a_ymax));
      gis::Cartesian_box b_box(gis::Cartesian_point(b_xmin, b_ymin),
                               gis::Cartesian_point(b_xmax, b_ymax));
      a_area = bg::area(a_box);
      if (a_area == 0.0) a_area = 0.001 * 0.001;
      bg::expand(a_box, b_box);
      *ab_area = bg::area(a_box);
    } else {
      assert(srs->is_geographic());
      gis::Geographic_box a_box(gis::Geographic_point(srs->to_radians(a_xmin),
                                                      srs->to_radians(a_ymin)),
                                gis::Geographic_point(srs->to_radians(a_xmax),
                                                      srs->to_radians(a_ymax)));
      gis::Geographic_box b_box(gis::Geographic_point(srs->to_radians(b_xmin),
                                                      srs->to_radians(b_ymin)),
                                gis::Geographic_point(srs->to_radians(b_xmax),
                                                      srs->to_radians(b_ymax)));
      bg::strategies::geographic<> strategies(bg::srs::spheroid<double>(
          srs->semi_major_axis(), srs->semi_minor_axis()));
      a_area = bg::area(a_box, strategies);
      bg::expand(a_box, b_box, strategies);
      *ab_area = bg::area(a_box, strategies);
    }
    if (std::isinf(a_area)) a_area = std::numeric_limits<double>::max();
    if (std::isinf(*ab_area)) *ab_area = std::numeric_limits<double>::max();
  } catch (...) {
    assert(false); /* purecov: inspected */
  }

  assert(std::isfinite(*ab_area - a_area));
  return *ab_area - a_area;
}

double rtree_area_overlapping(const dd::Spatial_reference_system *srs,
                              const uchar *mbr_a, const uchar *mbr_b,
                              int mbr_len [[maybe_unused]]) {
  assert(mbr_len == sizeof(double) * 4);

  double a_xmin = float8get(mbr_a);
  double a_xmax = float8get(mbr_a + sizeof(double));
  double a_ymin = float8get(mbr_a + sizeof(double) * 2);
  double a_ymax = float8get(mbr_a + sizeof(double) * 3);
  double b_xmin = float8get(mbr_b);
  double b_xmax = float8get(mbr_b + sizeof(double));
  double b_ymin = float8get(mbr_b + sizeof(double) * 2);
  double b_ymax = float8get(mbr_b + sizeof(double) * 3);

  assert(a_xmin <= a_xmax && a_ymin <= a_ymax);
  assert(b_xmin <= b_xmax && b_ymin <= b_ymax);

  double area = 0.0;
  try {
    if (srs == nullptr || srs->is_cartesian()) {
      gis::Cartesian_box a_box(gis::Cartesian_point(a_xmin, a_ymin),
                               gis::Cartesian_point(a_xmax, a_ymax));
      gis::Cartesian_box b_box(gis::Cartesian_point(b_xmin, b_ymin),
                               gis::Cartesian_point(b_xmax, b_ymax));
      gis::Cartesian_box overlapping_box;
      if (bg::intersection(a_box, b_box, overlapping_box)) {
        area = bg::area(overlapping_box);
      }
    } else {
      assert(srs->is_geographic());
      gis::Geographic_box a_box(gis::Geographic_point(srs->to_radians(a_xmin),
                                                      srs->to_radians(a_ymin)),
                                gis::Geographic_point(srs->to_radians(a_xmax),
                                                      srs->to_radians(a_ymax)));
      gis::Geographic_box b_box(gis::Geographic_point(srs->to_radians(b_xmin),
                                                      srs->to_radians(b_ymin)),
                                gis::Geographic_point(srs->to_radians(b_xmax),
                                                      srs->to_radians(b_ymax)));
      gis::Geographic_box overlapping_box;
      bg::strategies::geographic<> strategies(bg::srs::spheroid<double>(
          srs->semi_major_axis(), srs->semi_minor_axis()));
      if (bg::intersection(a_box, b_box, overlapping_box, strategies)) {
        area = bg::area(overlapping_box, strategies);
      }
    }
  } catch (...) {
    assert(false); /* purecov: inspected */
  }

  if (std::isnan(area)) area = 0.0;
  return area;
}
