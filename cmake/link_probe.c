// This source file exists only to create a dummy executable target, so that
// library targets can be linked to it in CMake. The goal is to have a vanilla
// target with no build instructions but that will "gather up" the final link
// line, which will be queried in some way (e.g., a link wrapper script, or
// the CMake File API, etc.)

int main() { return 0; }
