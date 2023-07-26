# flask-jwt-simple-cookie-auth

(JWT = JavaScript Web Tokens) 

## Description

Inspired by flask-jwt-extended, but I pared down the code to only support cookie-based auth (Access/Refresh/CSRF tokens)

## Why use JWT user Authentication?

Cookie-based JWT user authentication offers several benefits that make it a popular choice for user authentication in web applications:

1. Stateless: JWTs are self-contained, meaning all the necessary user information is included within the token itself. This allows the server to verify the user's identity without the need for additional server-side storage, making it stateless and scalable.

2. Cross-Origin Request Sharing (CORS): Cookies are automatically sent with every request to the same domain, including cross-origin requests, which can simplify authentication across multiple services or subdomains.

3. Same-Origin Policy: Cookies adhere to the Same-Origin Policy, which means they are only accessible by the domain that set them. This provides an additional layer of security and prevents client-side scripts from accessing the cookie from other domains.

4. CSRF Protection: By using HttpOnly and Secure flags in cookies, you can help protect against Cross-Site Request Forgery (CSRF) attacks, as these flags prevent client-side scripts from accessing cookies, making it harder for attackers to forge requests.

5. Automatic Inclusion: Cookies are automatically included in HTTP requests, which means you don't need to manually add authentication headers to every request made to the server.

6. Browser Support: Cookies are natively supported by browsers, making implementation and usage straightforward without the need for additional libraries.

7. Session Management: JWTs can be configured with a short expiration time, enabling them to act as session tokens, providing better control over user session management.

8. Scalability: Since JWTs are self-contained, the server does not need to maintain session information, resulting in reduced server load and better scalability for handling large numbers of concurrent users.

