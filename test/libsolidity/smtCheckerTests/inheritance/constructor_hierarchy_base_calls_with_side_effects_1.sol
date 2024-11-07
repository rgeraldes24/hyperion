contract A {
	uint public x;
	constructor(uint a) { x = a; }
}

contract B is A {
	constructor(uint b) A(b + f()) {
	}

	function f() internal returns (uint) {
		x = x + 1;
		return x;
	}
}

abstract contract T is A {
	uint k;
	constructor(uint t) {
		k = t;
	}
}

contract C is T, B {
	constructor() B(x) T(x) {
		assert(x == 1);
		assert(k == 0);
		assert(x == k); // should fail
	}
}
// ====
// SMTEngine: all
// SMTIgnoreCex: yes
// ----
// Warning 4984: (105-112): CHC: Overflow (resulting value larger than 2**256 - 1) happens here.
// Warning 6328: (351-365): CHC: Assertion violation happens here.
// Info 1391: CHC: 3 verification condition(s) proved safe! Enable the model checker option "show proved safe" to see all of them.
