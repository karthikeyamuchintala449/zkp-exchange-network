pragma circom 2.0.0;

// Import the comparison component from circomlib
include "../node_modules/circomlib/circuits/comparators.circom";

template AgeProof() {
    // Inputs 
    signal input birthdate;     // Private
    signal input current_date;   // Public

    // Constants
    var SECONDS_PER_YEAR = 31536000; // Note: Fixed missing 0 (31,536,000)
    var MINIMUM_AGE = 18;
    var MINIMUM_SECONDS = MINIMUM_AGE * SECONDS_PER_YEAR;

    // Outputs
    signal output age_valid;

    // 1. Calculate age in seconds
    signal age_in_seconds;
    age_in_seconds <== current_date - birthdate;

    // 2. Instantiate a comparator component
    // 64-bit size prevents field arithmetic underflow/overflow wrapping
    component gte = GreaterEqThan(64);
    
    gte.in[0] <== age_in_seconds;
    gte.in[1] <== MINIMUM_SECONDS;

    // 3. Bind the outcome of the comparison directly to the output signal
    // age_valid will output 1 if true, 0 if false
    age_valid <== gte.out;

    // 4. Force the circuit to FAIL compilation if they are not an adult
    age_valid === 1; 
}

// Ensure current_date is declared public when instantiating main
component main {public [current_date]} = AgeProof();
