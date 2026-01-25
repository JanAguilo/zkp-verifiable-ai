## [Technical Challenges/Limitations](./sources_info.md#technical-challengeslimitations)
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

Perfect ZK:
- A proof system is perfect zero-knowledge if for any verifier there exists a simulator algorithm such that, given the same input x, it can ouput a conversation which is identically distributed to the transcripts of a conversation with the real prover. 
- A simulator is an algorithm that acts as the "fake prover" which, given only public details(e.g. input x), can generate a transcript (sequence of messages exchanged) that is indistinguishable from the interaction between real prover and verifier.
- Formal definition: a protocol is zero-knowledge if, for every verifier V', there exists a simulator S such that the distribution of
    - Real transcript (prover & verifier)

    - Simulated transcript (simulator & verifier) 

    are computationally/statistically/perfectly indistinguishable (depending on the flavor). 
- Naive explanation: basically, if the verifier can use a simulator algorithm to run the simulation itself and be identically distributed to the output with the conversations with the prover, it means that the verifier didn't learn anything from the prover. 

Computational ZKP:
- Most of the zkp are not perfect but computational-zk. This means that they rely on typical cryptographical proofs where it is assumed that there are no adversarial feasible algorithms.
- **Formal definition**: Let $(P, V)$ be an interactive proof system for some language $L$. We say that $(P, V)$ is computational zero-knowledge if for every probabilistic polynomial-time interactive machine $V^{*}$ there exists a probabilistic polynomial-time algorithm $M^{*}$ such that for all $x \in L$ the two ensembles are computationally indistinguishable:
  - $\{\langle P, V^{*} \rangle (x)\}_{x \in L}$
  - $\{M^{*}(x)\}_{x \in L}$

  Machine $M^{*}$ is called a simulator for the interaction of $V^{*}$ with $P$.

Auxiliar inputs:
- the verifier might already have extra information related to the secret before a zero-knowledge proof begins.
- True robustness in compliance ZKPs requires designing protocols that remain zero-knowledge even if the verifier holds unexpected external or side information.

## [ZK-FRAMEWORKS](sources_info.md#zero-knowledge-proof-frameworks)

3 Characteristics of ZKP (Section II (Page 3)):
- *Soundness*: Verifier ($V$) will know if the Prover ($P$) tries to verify a false statement.
- *Completeness*: Honest $P$ can convince $V$ if the statement is true
- *Zero-Knowledge*: $V$ will not know anything about the statement private input besides the fact that is true.

Differences between Interactive and Non-Interactive Proofs (Appendix A):
- *Interactive*: It requires the prover P various rounds of interactions to convince V that the statement is true. V sends random challenges to P until V is convinced that the proof is valid. Both P and V must stay online until V is convinced. Separate protocol for each V.
- *Non-Interactive*: The prover P only needs to generate a single proof to convince any V. Many non-interactive proofs aim to minimize size of the proof, requiring P to have high computational power.

In general, Interactive proofs are more scalable in terms of computational power of P but at the cost of having less Vs to verify a proof.

**ZK PROTOCOLS**
- **zk-SNARKs** (Zero-Knowledge Succinct Non-Interactive Arguments of Knowledge)
  - Non-interactive protocols that boast small proof size. 
  - Underlying cryptography: ECC (Elliptic Curves)
  - Drawbacks: a new trusted setup (a ceremony in which the keys used to proof and verify are created) is required for every new circuit (in other words, if you want to prove something different you have to create a setup every time, which is computationally intensive). However, some recent work have introduced zk-SNARKs that use universal setups, or even no setup is required.   
  - **PLONKs** are a subset of zk-SNARK that works with a universal trusted setup (no need for a setup every time) but comes at a cost of higher performance cost (2-5x larger proof size than zk-SNARK, but still in the KB range).
- **zk-STARKs** (Zero-Knowledge Scalable Transparent Arguments of Knowledge)
  - No trusted setup needed, they use publicly randomness to generate the necessary parameters for proof and verification.
  - Underlying cryptography (hash functions) --> post-quantum security.
  - Drawbacks: proof sizes are much larger than zk-SNARKs and PLONKs and require more computational resources to generate and verify.
  - The cost comes from the underlying data structures used for generating proofs, called Merkle Trees.
  - How it works
    1. Express computations as an execution tree using Merkle Trees
    2. Arithmetize the computation trace (compute polynomials) during proof generation by encoding the trace in polynomial form.
    3. Instead of sending the entire trace, you compute evaluations of the polynomials at certain points, which are the leaf nodes. The root of the Merkle Tree acts as a commitement.
    4. Low-degree testing via FRI (FRI is a protocol that lets the verifier challenge the prover at a small number of random points)
    5. The verifier only needs to verify the root, a small set of polynomial evaluations using hash functions. 

## [ZKP MARKET](sources_info.md#proophy-a-zkp-market-mechanism)

A market for ZKP is proposed where there exist users that has some tasks that need to be proved and creates a bid for each task depending on the value the user assigns to the prove, and then there are the provers, where they specify the capacity s of tasks and the cost p of each task. Then, a market mechanism is in charge of allocation and payments.

## OWN SUMMARIZED NOTES
- Interactive proofs: the prover generates a proof specific for each verifier
- Non-interactive proofs: the prover generates only one proof which can be used for any verifier.
- Offline verification: the verifier is not involved at the moment of the proof generation. The proof is received later (for instance via blockchain) —> non-interactive proofs are offline while interactive are online (present and involved in the process)
- Succint —> short and fast to verify
- ZK-SNARKS:
    - Succint
    - Generally trusted setup
    - Elliptic curve cryptography —> not post-quantum secure (at least currently)
    - Small prove size (few hundred bytes)
    - Fast verification (milliseconds)
    - Zcash uses Halo 2, no trusted setup needed, fast verification and small proof size.
- ZK-STARKS:
    - Large proof size (tens or hundreds of KB)
    - No trusted setup required
    - Relies on hash function —> post-quantum secure
    - verification time slightly higher than zk-snarks but still fast (milliseconds also)
- Commitement schemes: they work like a sealed envelope. One can place a fixed value and then can be revealed, but only once. You cannot open the envelope, change it, and then open it again.
- In any ZKP that proves a statement about a computation, we need to represent the program as a circuit or constraints. ZKP uses R1CS or arithmetic circuits. The entire program with all intermediate values becomes a system of equations the prover must satisfy with their secret witness
- Fiat-Shamir used to eliminate interaction
