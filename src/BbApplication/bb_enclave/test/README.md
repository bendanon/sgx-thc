# Unit Tests for Black Box

To run unit tests for the black box module you need to first create the make file:
``cmake -DCMAKE_BUILD_TYPE=Debug``
Then compile the test:
``make``
Then run it:
``./runTests``
The expected output is:
``
[==========] Running 2 tests from 2 test cases.
[----------] Global test environment set-up.
[----------] 1 test from bbxTest
[ RUN      ] bbxTest.FullMesh_10
[       OK ] bbxTest.FullMesh_10 (129 ms)
[----------] 1 test from bbxTest (129 ms total)

[----------] 1 test from graphTest
[ RUN      ] graphTest.bfs_10
[       OK ] graphTest.bfs_10 (0 ms)
[----------] 1 test from graphTest (0 ms total)

[----------] Global test environment tear-down
[==========] 2 tests from 2 test cases ran. (129 ms total)
[  PASSED  ] 2 tests.
``
