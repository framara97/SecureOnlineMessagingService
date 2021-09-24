# Secure Online Messaging Service
The goal of the project is to implement a secure chat application among two clients. The communication 
must be confidential, authenticated and protected against replay attacks. Users are already
registered on the server through public keys that they use to authenticate. After the log-in, a user can
see other available users logged to the server. An user can send a "Request to Talk" (RTT) message
to another user. The user who receives the RTT can either accept or refuse. If the request is accepted,
the users proceed to chat through the server. Instead, if the request is refused, the users are not going
to chat.
