package store

func NewStore() (Store, error) {
	return NewMemoryStore(), nil
}
