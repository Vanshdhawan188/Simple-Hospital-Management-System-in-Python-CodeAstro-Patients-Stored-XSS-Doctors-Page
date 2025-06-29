## Vulnerability Summary
A critical Stored Cross-Site Scripting (XSS) vulnerability was discovered in the Available Doctor's file of CodeAstro Simple Hospital Management System in Python.
Attackers can inject malicious JavaScript via the patname field (POST parameter), which gets persistently stored in the database and executed whenever the profile page is viewed.

## Key Details

| Property             | Value                                                                 |
|----------------------|------------------------------------------------------------------------|
| **Affected Vendor**  | CodeAstro                                                              |
| **Vulnerable File**  | `doctor.html`                                                     |
| **Attack Vector**    | `First Name, Last name, Address` parameter via POST request                                   |
| **Vulnerability Type** | Stored Cross-Site Scripting (XSS)                                   |
| **Version Affected** | v1.0                                                                   |
| **Official Website** | [Simple Python Hospital Management System](https://codeastro.com/simple-hospital-management-system-in-python-with-source-code/)) |

## Proof of Concept (PoC)

### Step 1: Navigate to the Python Simple Hospital Management System Patient's Section

Navigate to the Available Doctor Section:

```
(http://localhost:8000/doctor.html)
```

![image](https://github.com/user-attachments/assets/95273f99-95a6-4d22-8c1d-e01cd938881d)

### Step 2: Inject XSS Payload in Name Field
Navigate To The Add Doctor Inside The Patient.html Page:
![image](https://github.com/user-attachments/assets/1c1b01ff-1953-4230-9c5e-adc560328589)

Paste the following payload in the "First Name And Last Name And Comments" input field and click Save Info After Filling Other Information:

```html
<script>alert(1)</script>
```
![image](https://github.com/user-attachments/assets/bfc2c872-714c-4830-8d74-15fc01833db5)


### Step 3: Trigger the Payload

Reload the profile page.  
You’ll see a JavaScript `alert(1)` triggered — confirming the stored XSS vulnerability.

Also, refreshing the page again will show the alert repeatedly. and if anyone open Patient.html Popup will also occur:
![image](https://github.com/user-attachments/assets/e44e6687-56c9-469c-a098-8d014e47eaaf)
![image](https://github.com/user-attachments/assets/69a4fe96-a480-4623-8663-e230a825473d)

## Potential Impact

- **Session Hijacking** – Steal user/admin session cookies via `document.cookie`.
- **Phishing** – Inject fake forms to harvest credentials.
- **Defacement** – Alter webpage content, defame the brand.
- **Data Exfiltration** – Steal sensitive data through background requests.
- **Malware Propagation** – Redirect users to malicious domains.
- **Privilege Escalation** – Gain access to higher-privilege accounts by exploiting stored scripts.

---

## Mitigation Strategies

### Input Sanitization

Sanitize all user inputs on the server side using:

```php
htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
```

### Output Encoding

Encode output before rendering dynamic content:

```php
echo htmlentities($user_input, ENT_QUOTES, 'UTF-8');
```

### Content Security Policy (CSP)

Implement a strong CSP header to prevent inline script execution:

```
Content-Security-Policy: default-src 'self'; script-src 'self';
```

### Use Modern Frameworks

Use frameworks like Laravel, Symfony, or CodeIgniter, which offer built-in XSS protection.

### Security Testing

Perform regular penetration testing using tools such as:

- OWASP ZAP
- Burp Suite

---

## References and Resources

- [OWASP XSS Prevention Cheat Sheet](https://owasp.org/www-community/xss-prevention)
- [Content Security Policy (CSP) Guide - MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [PHP htmlspecialchars()](https://www.php.net/manual/en/function.htmlspecialchars.php)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices/)

---

**Author:** Subhash Paudel  
**Date:** 2025-06-29  
**Severity:** High
