#include <openssl/evp.h>
#include <string>
#include <vector>

#define HMAC_HASH EVP_sha512

class TOTPGenerator {
public:
  TOTPGenerator();

  /**
   * Generates a time-based OTP (TOTP) based on the current time and the configured time step.
   * @param timeStep (optional) Time step in seconds (default: 30).
   * @return The generated OTP as a 6-digit string.
   * @throws std::runtime_error on any error during HMAC or digest calculation.
   */
  std::string generateTOTP(uint64_t timeStep = 30) const;

private:
  std::string secretKey_;
};


