/// The red Dart fixture: the planted finding is an implicit cast from dynamic, which
/// strict-casts reports, so the Dart gate must fail.
int add(dynamic a, int b) => a + b;
