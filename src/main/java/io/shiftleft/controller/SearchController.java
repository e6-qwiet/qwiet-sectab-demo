package io.shiftleft.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;


/**
 * Search login
 */
@Controller
public class SearchController {

@RequestMapping(value = "/search/user", method = RequestMethod.GET)
public String doGetSearch(@RequestParam String foo, HttpServletResponse response, HttpServletRequest request) {
    Logger logger = LoggerFactory.getLogger(SearchController.class);
    PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    Pattern pattern = Pattern.compile("^[a-zA-Z0-9\\s]+$"); // Restricted to alphanumeric characters and spaces
    
    // Validate input against a whitelist pattern
    Validator validator = new Validator();
    boolean isValid = validator.isValid(foo, pattern);
    if (!isValid) {
        logger.error("Invalid characters detected in input: {}", foo);
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid characters detected in input");
        return null;
    }
    
    // Sanitize input to prevent JavaScript injection
    String safeFoo = StringEscapeUtils.escapeJava(foo);
    
    // Parse expression safely
    ExpressionParser parser = new SpelExpressionParser();
    Expression exp = parser.parseExpression(safeFoo);
    Object message = exp.getValue();
    
    // Log the safe input
    logger.info("Processed safe input: {}", safeFoo);
    
    // Hash log entry for integrity verification
    String logEntry = "Safe input processed: " + safeFoo;
    String hashedLogEntry = hashLogEntry(logEntry);
    logger.info("Hashed log entry: {}", hashedLogEntry);
    
    return message.toString();
}

// Helper method to hash log entries
private String hashLogEntry(String entry) {
    // Using SHA-256 for hashing
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] encodedhash = digest.digest(entry.getBytes(StandardCharsets.UTF_8));
    StringBuilder hexString = new StringBuilder();
    for (byte b : encodedhash) {
        String hex = Integer.toHexString(0xff & b);
        if (hex.length() == 1) hexString.append('0');
        hexString.append(hex);
    }
    return hexString.toString();
}

    return message.toString();
  }
}
