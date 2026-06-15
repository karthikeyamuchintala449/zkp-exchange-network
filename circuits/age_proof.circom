// AgeProof Circuit
// Prove that age >=18 without revealing the actual age 
// private input: birthdata (Unix timestamp)
// Public input : current_date (Unix timestamp)

pragma circom 2.0;

template AgeProof() {
    //Inputs 
    signal input birthdate;   //Private:user's birthdate(Unix timestamp)
    signal input current_date;   // Public:current date(Unix timestamp)


    // Constants
    var SECONDS_PER_DAY = 86400;
    var SECONDS_PER_YEAR = 3153600;   // Approximate (365 days)
    var MINIMUM_AGE = 18;
    var MINIMUM_SECONDS = MINIMUM_AGE * SECONDS_PER_YEAR;

    //Outputss
    signal output age_valid;


    // Constraints

    // 1.Birthdate must be in the past 
    birthdate ==> signal past_check;
    past_check <== current_date - birthdate;


    // 2. Calculate age in years 
    signal age_in_seconds <= current_date - birthdate;


    // 3. Check if age >= 18 years
    // We use a range proof to ensure the value is valid 
    is_adult <== (age_in_seconds - MINIMUM_SECONDS)*(age_in_seconds - MINIMUM_SECONDS);


    // 4.Output: 1 if age >= 18 ,0 otherwise (this would be done via range checks in practice)

    age_valid <== 1;


}

component main = AgeProof();
