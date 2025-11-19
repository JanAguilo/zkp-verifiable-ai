## [Technical Challenges/Limitations](./sources_info.md#zk-frameworks)
In section 5.4.1 Verifiable Audits, many challenges are exposed:
- How to inform the user/client in a human-understandable the outputs of the verification.
- Since high computational cost is required, it's still an issue how zkp apply to large models such as OpenAI
- Changes on the models can happen more often than audits of that model


## [ZK-FRAMEWORKS](sources_info.md#zero-knowledge-proof-frameworks)

3 Characteristics of ZKP (Section II (Page 3)):
- *Soundness*: Verifier (V) will know if the Prover (P) tries to verify a fals statement.
- *Completeness*: Honest P can convince V if the statement is true
- *Zero-Knowledge*: V will not know anything about the statement private input besides the fact that is true.

Differences between Interactive and Non-Interactive Proofs (Appendix A):
- *Interactive*: It requires the prover P various rounds of interactions to convince V that the statement is true. V sends random challenges to P until V is convinced that the proof is valid. Both P and V must stay online until V is convinced. Separate protocol for each V.
- *Non-Interactive*: The prover P only needs to generate a single proof to convince any V. Many non-interactive proofs aim to minimize size of the proof, requiring P to have high computational power.

In general, Interactive proofs are more scalable in terms of computational power of P but at the cost of having less Vs to verify a proof.







