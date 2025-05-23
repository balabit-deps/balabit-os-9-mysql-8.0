/*
  Copyright (c) 2019, 2025, Oracle and/or its affiliates.

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
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
*/
#ifndef _table_column_iterator_h
#define _table_column_iterator_h

#include "my_bitmap.h"  // MY_BITMAP
#include "sql/field.h"  // Field
#include "sql/table.h"  // TABLE

/**
  @class Table_columns_view

  This template class acts as a container of table columns and encapsulates and
  abstracts a `TABLE` object field set iteration logic, by providing an iterator
  interface implementation.

  The template parameter `ExclusionFilter` is a predicate that takes a `TABLE`
  reference and a column index and returns whether or not the field should be
  filtered out, more specifically, a signature compatible with:

    std::function<bool (TABLE const*, size_t)>

  This template class accepts an empty parameter set, which provides an
  unfiltered container and iterates over all the table columns:

    void print_all_fields(TABLE *table) {
      Table_columns_view<> fields{table};

      for (auto field : fields) {
        std::cout << field->field_index << ". " << field << std::endl
                  << std::flush;
      }
    }

  The template parameter predicate may take the form of a `operator()`:

    class JSON_fields {
     public:
      bool operator()(TABLE const *table, size_t column_index) {
        return table->field[column_index]->type() != MYSQL_TYPE_JSON;
      }

      void print_json_fields(TABLE *table) {
        Table_columns_view<JSON_fields &> fields{table, *this};
        for (auto field : fields) {
          std::cout << field->field_index << ". " << field << std::endl
                    << std::flush;
        }
      }
    };

  The template parameter predicate may take the form of a lambda function:

    void print_int_fields(TABLE *table) {
      Table_columns_view<> fields{
          table, [](TABLE const *table, size_t column_index) -> bool {
            return table->field[column_index]->type() != MYSQL_TYPE_INT24;
          }};

      for (auto field : fields) {
        std::cout << field->field_index << ". " << field << std::endl
                  << std::flush;
      }
    }

  The list of generated columns is kept separately in the `TABLE` class, in
  the `TABLE::vfield` member. Although we could achieve accurate filtering
  using the above described methods, as a performance optimization, this
  class allows applying the filter and iteration directly and exclusively
  on the generated columns. For that we can use the `VFIELDS_ONLY` option:

    void print_virtual_generated_columns(TABLE *table) {
      Table_columns_view<> fields{
          table, [](TABLE const *table, size_t column_index) -> bool {
            return table->field[column_index]->is_virtual_gcol();
          },
          Table_columns_view<>::VFIELDS_ONLY
      };

      for (auto field : fields) {
        std::cout << field->field_index << ". " << field << std::endl
                  << std::flush;
      }
    }
 */
template <typename ExclusionFilter = std::function<bool(TABLE const *, size_t)>>
class Table_columns_view {
 public:
  /**
    Alias for the predicate type, for readability purposes.
   */
  using filter_fn_type = ExclusionFilter;

  /**
    Default set of options.
   */
  static constexpr unsigned long DEFAULTS = 0;
  /**
    Request the view excluding filter to operate `TABLE::vfields` instead
    of the full set.
  */
  static constexpr unsigned long VFIELDS_ONLY = 1;

  /**
    Empty constructor, only available when the predicate type is a lambda
    function.

    @param options optional parameter for filtering and iterating
                   options. Options should be combined with `|`. Available
                   options are `VFIELDS_ONLY`.
   */
  template <typename U = ExclusionFilter>
  Table_columns_view(
      unsigned long options = 0,
      typename std::enable_if<std::is_same<
          U, std::function<bool(TABLE const *, size_t)>>::value>::type * =
          nullptr);
  /**
    Constructor that takes the target `TABLE` object, only available when the
    predicate type is a lambda function.

    @param table reference to the target TABLE object.
    @param options optional parameter for filtering and iterating
                   options. Options should be combined with `|`. Available
                   options are `VFIELDS_ONLY`.
   */
  template <typename U = ExclusionFilter>
  Table_columns_view(
      TABLE const *table, unsigned long options = 0,
      typename std::enable_if<std::is_same<
          U, std::function<bool(TABLE const *, size_t)>>::value>::type * =
          nullptr);
  /**
    Constructor which takes a predicate used to filter this container iteration.

    @param filtering_predicate the predicate to filter this container iteration.
    @param options optional parameter for filtering and iterating
                   options. Options should be combined with `|`. Available
                   options are `VFIELDS_ONLY`.
   */
  Table_columns_view(ExclusionFilter filtering_predicate,
                     unsigned long options = 0);
  /**
    Constructor which takes the TABLE object whose field set will be iterated
    and a predicate used to filter this container iteration.

    @param table reference to the target TABLE object.
    @param filtering_predicate the predicate to filter this container iteration.
    @param options optional parameter for filtering and iterating
                   options. Options should be combined with `|`. Available
                   options are `VFIELDS_ONLY`.
   */
  Table_columns_view(TABLE const *table, ExclusionFilter filtering_predicate,
                     unsigned long options = 0);
  /**
    Destructor for the class.
   */
  virtual ~Table_columns_view();
  /**
    Setter which initializes the internal reference to the TABLE object whose
    field set will be iterated over.

    @param rhs reference to the target TABLE object

    @return a reference to this object.
   */
  virtual Table_columns_view &set_table(const TABLE *rhs);
  /**
    Setter which initializes the internal filtering predicate of type
    `ExclusionFilter`.

    @param rhs reference to the target filtering predicate `ExclusionFilter`

    @return a reference to this object.
   */
  virtual Table_columns_view &set_filter(ExclusionFilter rhs);

  // --> Deleted constructors and methods to remove default move/copy semantics
  Table_columns_view(const Table_columns_view &rhs) = delete;
  Table_columns_view(Table_columns_view &&rhs) = delete;
  Table_columns_view &operator=(const Table_columns_view &rhs) = delete;
  Table_columns_view &operator=(Table_columns_view &&rhs) = delete;
  // <--

  /**
    Iterator class to allow iterating over the replicatable fields in a TABLE
    object field set. It implements the bidirectional iterator concept.

    In order to fully understand this class implementation, please, check the
    documentation on the Iterator concept requirements within the C++ standard
    and the STL definition.
   */
  class iterator {
   public:
    using difference_type = std::ptrdiff_t;
    using value_type = Field *;
    using pointer = Field *;
    using reference = Field *;
    using iterator_category = std::bidirectional_iterator_tag;
    /**
      Constructor for the iterator. It takes the parent Table_columns_view
      object and the initial positions for the replicated table and for the
      local table.

      @param parent reference to the target Table_columns_view object.
      @param pos initial replicated table field set position.
      @param col initial local table field set position.
     */
    explicit iterator(Table_columns_view &parent, long pos, long col);
    /**
      Constructor for the iterator. It takes the parent Table_columns_view
      object and the initial positions for the replicated table and for the
      local table. It also includes a translation factor so we can get the
      iterated position in relation to a different set of columns.

      @note When this iterator is used in the context of a replica that is
      applying an event, the translation offset represents the number of extra
      columns that the event has to the left of other columns, which the table
      does not have (if any). So, for example, when the event has a GIPK column
      to the left, and the replica does not have that, then the offset is 1.

      @param parent reference to the target Table_columns_view object.
      @param pos initial replicated table field set position.
      @param col initial local table field set position.
      @param translation_offset the translation offset for translated_pos()
     */
    explicit iterator(Table_columns_view &parent, long pos, long col,
                      long translation_offset);
    /**
      Copy constructor.

      @param rhs object instance we pretend to copy from.
     */
    iterator(const iterator &rhs);
    /**
      Default destructor
     */
    virtual ~iterator() = default;
    // BASIC ITERATOR METHODS //
    iterator &operator=(const iterator &rhs);
    iterator &operator++();
    reference operator*() const;
    // END / BASIC ITERATOR METHODS //
    // INPUT ITERATOR METHODS //
    iterator operator++(int);
    pointer operator->() const;
    bool operator==(iterator rhs) const;
    bool operator!=(iterator rhs) const;
    // END / INPUT ITERATOR METHODS //

    // OUTPUT ITERATOR METHODS //
    // reference operator*() const; <- already defined
    // iterator operator++(int); <- already defined
    // END / OUTPUT ITERATOR METHODS //
    // FORWARD ITERATOR METHODS //
    // Enable support for both input and output iterator <- already enabled
    // END / FORWARD ITERATOR METHODS //

    // BIDIRECTIOANL ITERATOR METHODS //
    iterator &operator--();
    iterator operator--(int);
    // END / BIDIRECTIOANL ITERATOR METHODS //
    /**
      Returns the position this iterator object is pointing to, within the
      local table field set.

      @return the position this object is pointing to, within the local table
              field set.
     */
    size_t absolute_pos();
    /**
      Returns the position this iterator relative to the set of table columns
      which are not excluded by the associated filters

      @return the position this object is pointing to considering the non
              filtered columns
     */
    size_t filtered_pos();
    /**
      Returns the position this iterator object is pointing to, within the
      replicated table field set plus the translation_offset

      @note When this iterator is used in the context of a replica that is
      applying an event, use translated_pos to get the position within the
      event."

      @return the position this object is pointing to, within the replicated
              table field set adjusted to another frame of reference.
     */
    size_t translated_pos();

    friend struct TABLE;
    friend class Table_columns_view;

   private:
    /** A reference to the instance we wish to iterate over. */
    Table_columns_view const *m_parent;
    /**
      The position, relative to the TABLE object, this instance iterator is
      pointing to.
    */
    long m_absolute_pos;
    /**
      The position, relative to the set of included fields, this instance
      iterator is pointing to.
    */
    long m_filtered_pos;
    /**
      Translation unit used on top of the iterator filtered position, so
      we can adjust the position to another frame of reference.

      When this iterator is used in the context of a replica that is applying an
      event, use translated_pos to get the position within the event. This
      number should be set to N when the event has N extra columns to the left,
      which do not exist in the replica table.
    */
    long m_translation_offset;
  };

  /**
    Computes the total number of fields in the table.

    @return the number of fields in the table.
   */
  size_t absolute_size() const;
  /**
    Computes the total number of fields after filtering.

    @return the number of fields after filtering.
  */
  size_t filtered_size() const;
  /**
    Creates an iterator object, pointing at the beginning of the table field
    set.

    @return an iterator pointing to the beginning of the field set.
  */
  virtual iterator begin();
  /**
    Creates an iterator object, pointing at the end of the table field set.

    @return an iterator pointing to the end of the field set.
  */
  virtual iterator end();
  /**
    Returns whether or not the field at `index` is to be excluded from the field
    set iteration process.

    @param index the index of the field to test for exclusion from iteration.

    @return true if the field is to be excluded from the iteration, false
            otherwise.
  */
  bool is_excluded(size_t index) const;
  /**
    Returns the bitmap for the columns from the local table set that are to be
    included in the replicated row.

    @return a bitmap indicating which columns from the local table are to be
            included in the replicated row.
  */
  MY_BITMAP &get_included_fields_bitmap();
  /**
    Returns the bitmap for the columns from the local table set that are to be
    excluded from the replicated row.

    @return a bitmap indicating which columns from the local table are to be
            excluded from the replicated row.
  */
  MY_BITMAP &get_excluded_fields_bitmap();
  /**
    Takes a bitmap object, as received from the replication channel and
    translates it to a bitmap that matches the local TABLE object.

    @param[in]  source the bitmap as received from the replication channel
    @param[out] destination the bitmap that matches the local TABLE format

    @return this object reference (for chaining purposes).
  */
  Table_columns_view &translate_bitmap(MY_BITMAP &source,
                                       MY_BITMAP &destination);

  /**
    For the absolute position on the table that equals the given position given
    as a parameter, return the translated position.

    @param source the position in the local table

    @return the translated position within the local table.
  */
  size_t translate_position(size_t source);

  /**
    Returns the iterator for the (absolute) position in the table.

    @param absolute_pos the position in the local table

    @return the iterator for the position, if found
  */
  iterator find_by_absolute_pos(size_t absolute_pos);

 protected:
  /**
    Initializes the internal included and excluded fields bitmaps. After each
    member is set, this method should be invoked in order to remake the bitmaps.

    @return this object reference (for chaining purposes).
   */
  Table_columns_view &init_fields_bitmaps();

 private:
  /**
    The TABLE object reference which contains the field set to be iterated over.
   */
  TABLE const *m_table{nullptr};
  /**
    ExclusionFiltering predicate to be invoked when determining if a column is
    to be included in the iteration.
   */
  ExclusionFilter m_filtering_predicate;
  /** Number of columns to include in iteration. */
  size_t m_filtered_size{0};
  /**
    Bitmap that holds the information about which columns from the local table
    are to be included in the replicated row.
   */
  MY_BITMAP m_included_fields_bitmap;
  /**
    Bitmap that holds the information about which columns from the local table
    are to be excluded from the replicated row.
   */
  MY_BITMAP m_excluded_fields_bitmap;
  /**
    Set of options to apply to view behaviour
   */
  unsigned long m_options{0};

  /**
    Default filtering predicate.
   */
  static bool default_filter(TABLE const *table, size_t column_index);
};

template <typename F>
template <typename U>
Table_columns_view<F>::Table_columns_view(
    unsigned long options,
    typename std::enable_if<std::is_same<
        U, std::function<bool(TABLE const *, size_t)>>::value>::type *)
    : m_filtering_predicate{Table_columns_view::default_filter},
      m_options{options} {
  this->set_filter(Table_columns_view::default_filter);
}

template <typename F>
template <typename U>
Table_columns_view<F>::Table_columns_view(
    TABLE const *table, unsigned long options,
    typename std::enable_if<std::is_same<
        U, std::function<bool(TABLE const *, size_t)>>::value>::type *)
    : m_filtering_predicate{Table_columns_view::default_filter},
      m_options{options} {
  this->set_filter(Table_columns_view::default_filter)  //
      .set_table(table);
}

template <typename F>
Table_columns_view<F>::Table_columns_view(F filtering_predicate,
                                          unsigned long options)
    : Table_columns_view{nullptr, filtering_predicate, options} {}

template <typename F>
Table_columns_view<F>::Table_columns_view(TABLE const *target,
                                          F filtering_predicate,
                                          unsigned long options)
    : m_filtering_predicate{filtering_predicate}, m_options{options} {
  this->set_filter(filtering_predicate)  //
      .set_table(target);
}

template <typename F>
Table_columns_view<F>::~Table_columns_view() {
  bitmap_free(&this->m_included_fields_bitmap);
  bitmap_free(&this->m_excluded_fields_bitmap);
}

template <typename F>
Table_columns_view<F> &Table_columns_view<F>::set_table(const TABLE *rhs) {
  this->m_table = rhs;
  this->init_fields_bitmaps();
  return (*this);
}

template <typename F>
Table_columns_view<F> &Table_columns_view<F>::set_filter(F rhs) {
  this->m_filtering_predicate = rhs;
  this->init_fields_bitmaps();
  return (*this);
}

template <typename F>
size_t Table_columns_view<F>::absolute_size() const {
  if (this->m_table == nullptr) return 0;
  return this->m_table->s->fields;
}

template <typename F>
size_t Table_columns_view<F>::filtered_size() const {
  return this->m_filtered_size;
}

template <typename F>
typename Table_columns_view<F>::iterator Table_columns_view<F>::begin() {
  typename Table_columns_view<F>::iterator to_return{*this, -1, -1};
  ++to_return;
  return to_return;
}

template <typename F>
typename Table_columns_view<F>::iterator Table_columns_view<F>::end() {
  typename Table_columns_view<F>::iterator to_return{
      *this, static_cast<long>(this->absolute_size()),
      static_cast<long>(this->filtered_size())};
  return to_return;
}

template <typename F>
bool Table_columns_view<F>::is_excluded(size_t index) const {
  return bitmap_is_set(&this->m_excluded_fields_bitmap, index);
}

template <typename F>
MY_BITMAP &Table_columns_view<F>::get_included_fields_bitmap() {
  return this->m_included_fields_bitmap;
}

template <typename F>
MY_BITMAP &Table_columns_view<F>::get_excluded_fields_bitmap() {
  return this->m_excluded_fields_bitmap;
}

template <typename F>
Table_columns_view<F> &Table_columns_view<F>::translate_bitmap(
    MY_BITMAP &source, MY_BITMAP &destination) {
  if (this->m_table == nullptr) return (*this);
  if (source.bitmap == nullptr) return (*this);

  bitmap_init(&destination, nullptr, this->m_table->s->fields);

  for (auto it = begin(); it != end(); ++it) {
    size_t source_pos = it.translated_pos();
    size_t abs_pos = it.absolute_pos();
    if (source_pos >= source.n_bits) break;
    if (bitmap_is_set(&source, static_cast<uint>(source_pos))) {
      bitmap_set_bit(&destination, static_cast<uint>(abs_pos));
    }
  }

  return (*this);
}

template <typename F>
typename Table_columns_view<F>::iterator
Table_columns_view<F>::find_by_absolute_pos(size_t absolute_pos) {
  return std::find_if(begin(), end(), [absolute_pos](auto it) {
    return it->field_index() == absolute_pos;
  });
}

template <typename F>
size_t Table_columns_view<F>::translate_position(size_t orig_pos) {
  for (auto it = begin(); it != end(); ++it) {
    size_t abs_pos = it.absolute_pos();
    if (abs_pos == orig_pos) return it.translated_pos();
  }
  return orig_pos;
}

template <typename F>
Table_columns_view<F> &Table_columns_view<F>::init_fields_bitmaps() {
  if (this->m_table == nullptr) return (*this);

  bitmap_free(&this->m_included_fields_bitmap);
  bitmap_free(&this->m_excluded_fields_bitmap);
  bitmap_init(&this->m_included_fields_bitmap, nullptr,
              this->m_table->s->fields);
  bitmap_init(&this->m_excluded_fields_bitmap, nullptr,
              this->m_table->s->fields);

  this->m_filtered_size = 0;
  if ((this->m_options & VFIELDS_ONLY) == VFIELDS_ONLY) {
    bitmap_set_all(&this->m_excluded_fields_bitmap);
    for (auto fld = this->m_table->vfield; *fld != nullptr; ++fld) {
      auto idx = (*fld)->field_index();
      if (!this->m_filtering_predicate(this->m_table, idx)) {
        bitmap_set_bit(&this->m_included_fields_bitmap, idx);
        bitmap_clear_bit(&this->m_excluded_fields_bitmap, idx);
        ++this->m_filtered_size;
      }
    }
  } else {
    for (size_t idx = 0; idx != this->m_table->s->fields; ++idx) {
      if (this->m_filtering_predicate(this->m_table, idx)) {
        bitmap_set_bit(&this->m_excluded_fields_bitmap, idx);
      } else {
        bitmap_set_bit(&this->m_included_fields_bitmap, idx);
        ++this->m_filtered_size;
      }
    }
  }
  return (*this);
}

template <typename F>
bool Table_columns_view<F>::default_filter(TABLE const *, size_t) {
  return false;
}

template <typename F>
Table_columns_view<F>::iterator::iterator(Table_columns_view &parent,
                                          long absolute_pos, long filtered_pos)
    : m_parent{&parent},
      m_absolute_pos{absolute_pos},
      m_filtered_pos{filtered_pos},
      m_translation_offset{0} {}

template <typename F>
Table_columns_view<F>::iterator::iterator(Table_columns_view &parent,
                                          long absolute_pos, long filtered_pos,
                                          long translation_offset)
    : m_parent{&parent},
      m_absolute_pos{absolute_pos},
      m_filtered_pos{filtered_pos},
      m_translation_offset{translation_offset} {}

template <typename F>
Table_columns_view<F>::iterator::iterator(const iterator &rhs) {
  (*this) = rhs;
}

template <typename F>
typename Table_columns_view<F>::iterator &
Table_columns_view<F>::iterator::operator=(
    const Table_columns_view<F>::iterator &rhs) {
  this->m_parent = rhs.m_parent;
  this->m_absolute_pos = rhs.m_absolute_pos;
  this->m_filtered_pos = rhs.m_filtered_pos;
  this->m_translation_offset = rhs.m_translation_offset;
  return (*this);
}

template <typename F>
typename Table_columns_view<F>::iterator &
Table_columns_view<F>::iterator::operator++() {
  if (this->m_parent->m_table != nullptr &&
      this->m_absolute_pos !=
          static_cast<long>(this->m_parent->absolute_size())) {
    do {
      ++this->m_absolute_pos;
    } while (this->m_absolute_pos !=
                 static_cast<long>(this->m_parent->absolute_size()) &&
             this->m_parent->is_excluded(this->m_absolute_pos));
    ++this->m_filtered_pos;
  }
  return (*this);
}

template <typename F>
typename Table_columns_view<F>::iterator::reference
Table_columns_view<F>::iterator::operator*() const {
  if (this->m_parent->m_table != nullptr &&
      this->m_absolute_pos !=
          static_cast<long>(this->m_parent->absolute_size())) {
    return this->m_parent->m_table->field[this->m_absolute_pos];
  }
  return nullptr;
}

template <typename F>
typename Table_columns_view<F>::iterator
Table_columns_view<F>::iterator::operator++(int) {
  typename Table_columns_view<F>::iterator to_return = (*this);
  ++(*this);
  return to_return;
}

template <typename F>
typename Table_columns_view<F>::iterator::pointer
Table_columns_view<F>::iterator::operator->() const {
  return this->operator*();
}

template <typename F>
bool Table_columns_view<F>::iterator::operator==(
    Table_columns_view<F>::iterator rhs) const {
  return this->m_absolute_pos == rhs.m_absolute_pos &&
         this->m_parent->m_table == rhs.m_parent->m_table;
}

template <typename F>
bool Table_columns_view<F>::iterator::operator!=(
    Table_columns_view<F>::iterator rhs) const {
  return !((*this) == rhs);
}

template <typename F>
typename Table_columns_view<F>::iterator &
Table_columns_view<F>::iterator::operator--() {
  if (this->m_parent->m_table != nullptr && this->m_absolute_pos != 0) {
    do {
      --this->m_absolute_pos;
    } while (this->m_absolute_pos != 0 &&
             this->m_parent->is_excluded(this->m_absolute_pos));
    --this->m_filtered_pos;
  }
  return (*this);
}

template <typename F>
typename Table_columns_view<F>::iterator
Table_columns_view<F>::iterator::operator--(int) {
  typename Table_columns_view<F>::iterator to_return = (*this);
  --(*this);
  return to_return;
}

template <typename F>
size_t Table_columns_view<F>::iterator::absolute_pos() {
  return static_cast<size_t>(this->m_absolute_pos);
}

template <typename F>
size_t Table_columns_view<F>::iterator::filtered_pos() {
  return static_cast<size_t>(this->m_filtered_pos);
}

template <typename F>
size_t Table_columns_view<F>::iterator::translated_pos() {
  return static_cast<size_t>(this->m_filtered_pos + this->m_translation_offset);
}

#endif  // _table_column_iterator_h
