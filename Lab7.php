<?php
require_once($_SERVER['DOCUMENT_ROOT'] . '/.core/account/user_records.php');
require_once($_SERVER['DOCUMENT_ROOT'] . '/.core/account/login_attempt_handler.php');
require_once($_SERVER['DOCUMENT_ROOT'] . '/.core/.utilities/validation_helper.php');
require_once($_SERVER['DOCUMENT_ROOT'] . '/.core/.utilities/safe_string_helper.php');
require_once($_SERVER['DOCUMENT_ROOT'] . '/.core/account/authorization_helper.php');

class AccountHandler
{
    public static function registerUser(
        ?string $email,
        ?string $fullName,
        ?string $dob,
        ?string $residence,
        ?string $gender,
        ?string $hobbies,
        ?string $socialLink,
        ?int    $bloodGroup,
        ?string $factor,
        ?string $password1,
        ?string $password2
    ) : ?array
    {
        $errors = [];

        if (AuthorizationHelper::isLoggedIn()) {
            $errors['general'] = 'Error: You are already logged in (refresh the page)';
            return $errors;
        }

        $email = ValidationHelper::sanitizeEmail($email);

        if ($error = ValidationHelper::validateEmail($email)) {
            $errors['email'] = $error;
        }
        else {
            $userRecord = UserRecords::getByEmail($email ?? null);

            if ($userRecord) {
                $errors['email'] = 'Email Error: User with this email already exists';
            }
        }

        $fields = [
            'fullName' => 'validateFullName',
            'dob' => 'validateDateOfBirth',
            'residence' => 'validateAddress',
            'gender' => 'validateGender',
            'hobbies' => 'validateMainInterests',
            'socialLink' => 'validateSocialLink',
            'bloodGroup' => 'validateBloodGroup',
            'factor' => 'validateFactor',
            'password1' => 'validatePassword'
        ];

        foreach ($fields as $field => $validator) {
            if ($error = ValidationHelper::$validator($$field)) {
                $errors["$field"] = $error;
            }
        }

        if ($passwordError = ValidationHelper::validatePasswordMatch($password1, $password2)) {
            $errors['password2'] = $passwordError;
        }

        if (count($errors)) {
            return $errors;
        }

        $hashedPassword = password_hash($password1, PASSWORD_BCRYPT);

        $newUser = UserRecords::create(
            $email,
            $fullName,
            $dob,
            $residence,
            $gender,
            $hobbies,
            $socialLink,
            $bloodGroup,
            $factor,
            $hashedPassword
        );

        if (!$newUser) {
            $errors['db'] = 'SQL Error: Unable to add user (contact support)';
            return $errors;
        }

        return null;
    }

    public static function loginUser(string $email, string $password) : ?string
    {
        if (AuthorizationHelper::isLoggedIn()) {
            return 'You are already logged in';
        }

        $email = ValidationHelper::sanitizeEmail($email);

        if ($error = ValidationHelper::validateEmail($email)) {
            return $error;
        }

        $userDetails = UserRecords::getByEmail($email);
        if (null == $userDetails) {
            return 'Email Error: No user found with this email';
        }

        $userId = $userDetails['id'];

        $timeRemaining = LoginAttemptHandler::timeUntilNextAttempt($userId);

        if (0 !== $timeRemaining) {
            return 'You have exceeded the maximum login attempts for the hour.' . '<br>'
                . 'Please try again in ' . SafeStringHelper::secondsToMinutesAndSeconds($timeRemaining);
        }

        $maxAttempts = LoginAttemptHandler::$MAX_ATTEMPTS;

        if (!password_verify($password, $userDetails['password'])) {
            LoginAttemptHandler::logAttempt($userId);
            $attemptsMade = LoginAttemptHandler::countAttempts($userId);

            return $maxAttempts - $attemptsMade > 0
                ? 'Incorrect password. Attempts remaining: ' . ($maxAttempts - $attemptsMade) . '.'
                : 'Incorrect password.' . '<br>' . 'Try again in ' .  SafeStringHelper::secondsToMinutesAndSeconds(LoginAttemptHandler::timeUntilNextAttempt($userId));
        }

        LoginAttemptHandler::resetAttempts($userId);
        AuthorizationHelper::setSessionUserId($userId);

        return null;
    }

    public static function logoutUser() : void
    {
        AuthorizationHelper::unsetSessionUserId();
    }

    public static function getCurrentUser() : ?array
    {
        $userId = AuthorizationHelper::getSessionUserId();

        if (null === $userId) {
            return $userId;
        }

        return UserRecords::getById($userId);
    }

    public static function resetPassword(string $email, string $newPassword): ?string
    {
        $user = UserRecords::getByEmail($email);
        if (!$user) {
            return 'Email Error: No user found with this email';
        }

        $hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT);
        if (UserRecords::updatePassword($email, $hashedPassword)) {
            return 'Password updated successfully';
        } else {
            return 'Error: Could not update password';
        }
    }
}
