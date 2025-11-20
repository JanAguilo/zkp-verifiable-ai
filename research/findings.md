## [Technical Challenges/Limitations](./sources_info.md#zk-frameworks)
In section 5.4.1 Verifiable Audits, many challenges are exposed:
- How to inform the user/client in a human-understandable the outputs of the verification.
- Since high computational cost is required, it's still an issue how zkp apply to large models such as OpenAI
- Changes on the models can happen more often than audits of that model


## [ZK-BASICS](sources_info.md#antonio-peso-tfg)
Turing Machines (algorithms):
- Turing machines process an input using a transition function that dynamically moves between states.
- If the state reached is the reject state, the machine rejects the input and outputs 0.
- If the state reached is the accept state, the machine accepts the input and outputs 1.

Interactive Turing Machine Schema:
- Verifier sends random challenge to the Prover, with bit 0, meaning that the prove has to be related to input x, or 1, meaning that the prove has to be related to something else, for instance a different bit of info. This challenge has some randomness to prevent the prover to prepare in advance. 
- The prover receives the challenge and sends the answer back to the verifier. 
- The verifier receives the message from the prover and checks. If the verification succeeds, then output 1 (success). Otherwise, output 0 (reject).
- Since only one party can be active (not both at the same time), there is a switch bit to handle that. Basically each party after doing the needed operation/s, they switch the bit so that the other party activates.

Properties of a proof
- Completeness: accept a true statement with a high probability
- Soundness: accepting a false statement with a low probability

4.1.2 pending


## [ZK-FRAMEWORKS](sources_info.md#zero-knowledge-proof-frameworks)

3 Characteristics of ZKP (Section II (Page 3)):
- *Soundness*: Verifier (V) will know if the Prover (P) tries to verify a fals statement.
- *Completeness*: Honest P can convince V if the statement is true
- *Zero-Knowledge*: V will not know anything about the statement private input besides the fact that is true.

Differences between Interactive and Non-Interactive Proofs (Appendix A):
- *Interactive*: It requires the prover P various rounds of interactions to convince V that the statement is true. V sends random challenges to P until V is convinced that the proof is valid. Both P and V must stay online until V is convinced. Separate protocol for each V.
- *Non-Interactive*: The prover P only needs to generate a single proof to convince any V. Many non-interactive proofs aim to minimize size of the proof, requiring P to have high computational power.

In general, Interactive proofs are more scalable in terms of computational power of P but at the cost of having less Vs to verify a proof.







