{
	switch 42
	case 1 {}
	case 1 {}
	default {}
}
// ====
// dialect: zvm
// ----
// DeclarationError 6792: (25-34): Duplicate case "1" defined.
