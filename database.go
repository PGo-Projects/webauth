package webauth

type Database interface {
	InsertOne(entry interface{}) error
	FindOne(filter interface{}) (interface{}, error)
}
