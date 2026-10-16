No opaque type with a lifetime touches borrowed data when it is dropped, through its own `Drop` or a field's.
.NET runs finalizers in no deterministic order, so the data it borrows may already be freed by then.
