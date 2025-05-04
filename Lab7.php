<?php
require_once($_SERVER['DOCUMENT_ROOT'] . '/.core/account/user_records.php');
require_once($_SERVER['DOCUMENT_ROOT'] . '/.core/account/login_attempt_handler.php');
require_once($_SERVER['DOCUMENT_ROOT'] . '/.core/.utilities/validation_Super_helper.php'); // 1
require_once($_SERVER['DOCUMENT_ROOT'] . '/.core/.utilities/safe_string_Super_helper.php'); // 1
require_once($_SERVER['DOCUMENT_ROOT'] . '/.core/user/authorization_helper.php'); // 1 3

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
            $errors['general'] = 'Вы уже авторизованы (перезагрузите страницу)'; // 11
            return $errors;
        }

        $email = ValidationHelper::sanitizeEmail($email);

        if ($error = ValidationHelper::validateEmail($email)) {
            $errors['email'] = $error;
        }
        else {
            $userRecord = UserRecords::getByEmail($email ?? null);

            if ($userRecord) {
                $errors['email'] = 'Email Error: User with this email already exists'; // 11
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
            'Rh_factor' => 'validateRh_Factor', //6
            'password1and2' => 'validatePassword1and2'//6
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
        $password=ValidationHelper;;sanitizePassword($password); //5 было :$password=ValidationHelper;;sanitizePassword($Address); //5 , 11
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

    public static function logoutUser() : boolean // 2
    {
       return AuthorizationHelper::unsetSessionUserId(); // 2
    }

    public static function getCurrentUser() : ?array
    {
        $userId = AuthorizationHelper::getSessionUserId();

        if (null === $password) { // 8
            return []; // 8 , 9
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
            return 'Error: Could not update password because the Validation is wrong for this user'; //7
        }
    }
}
