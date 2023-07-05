# gobware

Session Cookie based approach:

1. Server generates a "sessionId" (signs it using "secret key"), and 
(a) saves the sessionId in a sessionDB, and 
(b) sends a cookie with the sessionId to the browser (client side).
2. The browser (client side) receives the "cookie" in the response from server, and saves it in the "cookie" storage. 
3. The browser then includes the "cookie" within every subsequent request to the server.

JWT JSON Web Token approach:

1. Server generates an "accessToken", encrypting the "userId" and "expiresIn", with the ACCESS_TOKEN_SECRET, 
and sends the "accessToken" to the browser (client side).
2. The browser (client side) receives the "accessToken" and saves it on the client side.
3. The "accessToken" is included in every subsequent request to the server.

----------------------------------------------------------

Note:

In case of the JWT approach, the accessToken itself contains the encrypted “userId”, and the accessToken is not saved within any sessionDB.
Since no DB is required in case of the “jwt approach”, it is sometimes called “stateless” approach to managing sessions, since no “state” or “session” is saved within a DB (it is contained within the JWT token itself).
The JWT tokens are sometimes referred to as “Bearer Tokens” since all the information about the user i.e. “bearer” is contained within the token.
In case of the session cookie based approach, the sessionId does not contain any userId information, but is a random string generated and signed by the “secret key”.
The sessionId is then saved within a sessionDB. The sessionDB is a database table that maps “sessionId” < — -> “userId”.
Since sessionIds are stored in a sessionDB, the “session cookie approach” is sometimes called “stateful” approach to managing sessions, since the “state” or “session” is saved within a DB.

----------------------------------------------------------

Steps in Session Cookie based approach,

1. Get the "sessionId" from the request "cookie".
2. Verify the "sessionId" integrity using the "secret key". 
Then look up the "sessionId" within the sessionDB on the server and get the "userId".
3. Look up the "userId" within the shoppingCartDB to add items to cart for that userId, or display cart info for that userId.

Steps in JWT based approach,

1. Get the "accessToken" from the request "header".
2. Decrypt the "accessToken" i.e the JWT, using ACCESS_TOKEN_SECRET and get the "userId" ---> (there is no DB lookup).
3. Look up the "userId" within the shoppingCartDB to add items to cart for that userId, or display cart info for that userId.
