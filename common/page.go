package common

type Pageable struct {
	Page int32
	Size int32
	Sort string
}

func NewPageable(page, size int32, sort, defaultSort string) *Pageable {
	if page < 0 {
		page = 0
	}

	if size <= 0 {
		size = 20
	}

	if IsBlank(sort) {
		sort = defaultSort
	}

	return &Pageable{
		Page: page,
		Size: size,
		Sort: sort,
	}
}

func (p *Pageable) Limit() int64 {
	return int64(p.Size)
}

func (p *Pageable) Offset() int64 {
	return int64(p.Page) * int64(p.Size)
}

func (p *Pageable) TotalPages(totalElements int64) int32 {
	if totalElements <= 0 {
		return 0
	}

	if totalElements <= int64(p.Size) {
		return 1
	}

	result := int32(totalElements / int64(p.Size))

	if totalElements%int64(p.Size) > 0 {
		result += 1
	}

	return result
}

type Page[T any] struct {
	TotalElements int64
	TotalPages    int32
	First         bool
	Last          bool
	Page          int32
	Size          int32
	Content       []T
	Empty         bool
}

func NewPage[T any](pageable *Pageable, totalElements int64, content []T) *Page[T] {
	totalPages := pageable.TotalPages(totalElements)

	return &Page[T]{
		TotalElements: totalElements,
		TotalPages:    totalPages,
		First:         pageable.Page == 0,
		Last:          pageable.Page == totalPages-1,
		Page:          pageable.Page,
		Size:          pageable.Size,
		Content:       content,
		Empty:         len(content) == 0,
	}
}
