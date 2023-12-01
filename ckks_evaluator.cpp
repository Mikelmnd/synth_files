#include "ckks_evaluator.h"

void top_level_function(seal::SEALContext context,seal::Ciphertext &encrypted1, const seal::Ciphertext &encrypted2) {

    static seal::Evaluator evaluator(context);

    return  evaluator.add_inplace(encrypted1,encrypted2);
}