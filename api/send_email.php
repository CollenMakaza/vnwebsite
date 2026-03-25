<?php
// Enable error logging but don't display to users
ini_set('display_errors', 0);
ini_set('log_errors', 1);
error_reporting(E_ALL);

// Set headers for CORS and content type
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type");
header("Content-Type: application/json");

// Only allow POST requests
if ($_SERVER["REQUEST_METHOD"] != "POST") {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

// Get form data (works with both JSON and form-urlencoded)
$input = file_get_contents('php://input');
if (strpos($input, '{') === 0) {
    // JSON input
    $data = json_decode($input, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid JSON data']);
        exit;
    }
    $name = $data['Name'] ?? '';
    $email = $data['Email'] ?? '';
    $phone = $data['Phone'] ?? '';
    $message = $data['Message'] ?? '';
} else {
    // Form-urlencoded input
    parse_str($input, $data);
    $name = $data['name'] ?? '';
    $email = $data['email'] ?? '';
    $phone = $data['phone'] ?? '';
    $message = $data['message'] ?? '';
}

// Sanitize inputs
function sanitize_input($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    return $data;
}

$name = sanitize_input($name);
$email = sanitize_input($email);
$phone = sanitize_input($phone);
$message = sanitize_input($message);

// Validate inputs
if (empty($name) || empty($email) || empty($message)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'All fields are required']);
    exit;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Invalid email address']);
    exit;
}

// Honeypot check
if (!empty($data['website']) || !empty($data['url'])) {
    echo json_encode(['success' => true]);
    exit;
}

// Prepare email
$to = "admin@vulturenest.org";
$subject = "New Contact Form Submission from $name";
$email_content = "Name: $name\n";
$email_content .= "Email: $email\n";
$email_content .= "Phone: $phone\n\n";
$email_content .= "Message:\n$message";

$headers = "From: $name <$email>\r\n";
$headers .= "Reply-To: $email\r\n";
$headers .= "MIME-Version: 1.0\r\n";
$headers .= "Content-Type: text/plain; charset=UTF-8\r\n";
$headers .= "X-Mailer: PHP/" . phpversion();

// Additional security headers
$headers .= "X-Originating-IP: {$_SERVER['REMOTE_ADDR']}\r\n";
$headers .= "X-Mailer-Info: Contact Form Submission\r\n";

// Send email
try {
    $mail_sent = mail($to, $subject, $email_content, $headers);
    
    if ($mail_sent) {
        echo json_encode(['success' => true, 'message' => 'Thank you! Your message has been sent.']);
    } else {
        throw new Exception('Mail function failed');
    }
} catch (Exception $e) {
    error_log("Email sending error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Failed to send message. Please try again later.']);
}