## Run the target

Compile to dynamic library (`.so`):
```
go build -o bin/tlib.so -buildmode=c-shared main.go
```

NOTES: In order to compile to dynamic library you need the below things:
- File must be a main package 
- Must `import "C"`
- In order to generate a header file, every exported function must have the comment e.g. `//export Div` like an attribute
