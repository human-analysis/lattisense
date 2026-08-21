go build -buildmode=c-archive -o liblattigo.a main.go bootstrap.go c_struct_import_export.go conversion.go multiparty.go
go build -buildmode=c-shared -o liblattigo.so main.go bootstrap.go c_struct_import_export.go conversion.go multiparty.go
