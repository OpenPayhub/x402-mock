# x402-mock

## What is 402

You may have encountered the webpage error 404 (page not found), and also heard about the success code 200. But you might not know that in the internet protocols, a special code **402** was reserved.

At the dawn of the internet, engineers reserved the HTTP 402 status code, whose official definition is: **"Payment Required"**.

Simply put, if a resource (such as an in-depth report or a piece of accurate data) is not free, the system will return 402. Although it has been "shelved" for many years, in today's AI era, it is becoming the passport for machines to do business with each other.

## Why x402 is Needed

In the past, it was "humans" buying things online, with a slow process: selecting products, jumping to payment pages, scanning QR codes, entering passwords.

But with the explosion of AI Agents today, the protagonist has become **"robots"**. Imagine:

> Your AI assistant is helping you write a report. It needs to fetch the latest crypto market trends today, or purchase a piece of encrypted data from another AI. This request may only be worth 0.01 dollars.

If every few cents required human scanning and confirmation, the AI's work would be fragmented. The significance of x402 is to establish a standard that enables AI to perform these micro-payments automatically and at low cost, making the entire process as natural as breathing.

## Why Signatures Are Needed Instead of Direct Transfers

This might be the most concerned question: since we know the recipient's address, wouldn't a direct transfer suffice?

Actually, this involves a fundamental flaw in **"user experience"**:

- **Direct transfer = going to a bank counter**  
  On the blockchain, a real transfer confirmation often takes seconds or even minutes. If you have to wait 30 seconds every time you buy a few cents worth of news, the experience is disastrous.

- **Offline signature = signing a check**  
  x402 adopts a smarter approach. As the payer, you don't need to transfer on-chain immediately; instead, you sign a **"digital check"** (i.e., signature) with your private key.
  
  - **Millisecond response**: Signing this check takes less than 0.1 seconds.
  - **Receive first, cash later**: After receiving this "check", the recipient (the AI selling data) only needs to instantly verify the signature's authenticity, confirm you have funds and indeed signed it, and can immediately deliver the resource to you.

As for when this check is cashed at the bank (on-chain), the recipient can handle it asynchronously in the background, without affecting your current interaction experience at all.

## Core Concept of x402-mock: The Cinema Analogy

Building upon the X402 payment philosophy, x402-mock incorporates additional 'whitelist' mechanism features.
To better understand the design philosophy of x402-mock, we can use the example of a cinema:

**Scenario setup:**
- **Cinema (Server)**: Provides service (movies) and collects fees
- **Audience (Client)**: Enjoys service (watches movies) and pays fees
- **Ticket check**: Verifies whether the audience has valid tickets
- **Ticket office**: Sells movie tickets to the audience

**Payment flow analogy:**

1. **Audience enters (Client requests resource)**
   - The audience walks to the ticket check and presents the movie ticket
   - The Client sends a request to the Server, carrying an access token

2. **Ticket check (Server verifies token)**
   - The ticket checker verifies the ticket's authenticity and validity period
   - The Server verifies the validity of the access token

3. **No ticket handling (returns 402 status code)**
   - If the audience has no ticket or the ticket is expired, the ticket checker will say: "Please go to the ticket office to buy a ticket"
   - If the Client has no valid token, the Server returns a 402 status code + payment information

4. **Ticket purchase process (Client completes payment)**
   - The audience goes to the ticket office, selects a showtime, pays for the ticket
   - The Client, based on the payment information, uses a private key signature to complete the on-chain payment

5. **Re-check ticket (obtain access token)**
   - The audience returns to the ticket check with the new ticket
   - The Client sends the payment signature to the `/token` endpoint to obtain an access token

6. **Successful movie watching (obtain resource)**
   - The ticket check passes, the audience enters the screening hall to watch the movie
   - The Client re-requests with the new token and successfully obtains the resource

**Key to separation of responsibilities:**
- **Ticket check (Server business endpoint)**: Only responsible for verification, not handling ticket purchases
- **Ticket office (`/token` endpoint)**: Specifically handles payment and issuing tokens
- **Audience (Client)**: Automatically completes the entire process, seamless experience

This design achieves **separation of responsibilities**, decoupling payment logic from business logic, enhancing system security and maintainability.

## Next Steps

- Check [Quick Start](quick_start.md) for quick deployment
- Check [API Reference](reference.md) for detailed documentation
- Extended reading [Which Protocols Does x402 Use?](erc_eip_docs.md) to learn more about related knowledge
- Visit the GitHub repository for full content: https://github.com/OpenPayhub/x402-mock
- ⚠️ Test on testnet (e.g., Sepolia) before production use