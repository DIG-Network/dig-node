# dig-chat-protocol

The DIG Network chat message-TYPE layer: the five chat payload types — `ChatMessage`,
`DeliveryReceipt`, `ReadReceipt`, `TypingIndicator`, `Presence` — defined in `dig-message`'s reserved
dig-chat band (`0x0000_0200..=0x0000_02FF`) and registered into its `MessageRegistry`.

It is a crypto-free, content-blind layer: `ChatMessage::envelope` carries the opaque `DIGCHAT1`
content seal verbatim and is never parsed here; `dig-message` provides all seal / sign / replay /
streaming. See `SPEC.md`.
