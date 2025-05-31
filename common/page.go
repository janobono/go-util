package common

func TotalPages(pageSize int32, totalRows int64) int32 {
	if pageSize <= 0 || totalRows <= 0 {
		return 0
	}

	if totalRows <= int64(pageSize) {
		return 1
	}

	result := int32(totalRows / int64(pageSize))

	if totalRows%int64(pageSize) > 0 {
		result += 1
	}

	return result
}

func AbsInt32(n int32) int32 {
	if n < 0 {
		return -n
	}
	return n
}

func AbsInt64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}
