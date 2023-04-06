## Meeting Reports and Updates on the [ERO project](docs/ero-proposal.pdf) 
`Project progress`: ![4%](https://progress-bar.dev/4)

### TOC
#### Meetings
[Meeting 00](#m00)


#### Updates
[Update 00](#u00)

## Meeting 00
### Title: Tentative workplan
### Date: 25-06-2020
We had a quick discussion on the project in general and the different (tentative) steps we plan to take, which I will outline below. Preferably we will keep things in line with the different technical objectives outlined in the project proposal.
1. As a first step we plan to work a little with GraalVM so as to get a better idea of the inner workings of the latter. I've seen many interesting papers on the project website, as well as those shared by Valerio Schiavoni (https://www.cs.hku.hk/data/techreps/document/TR-2020-06.pdf ) which we will go through too. These will help understand better how the system works and give us ideas on how to proceed.
2. Once we get versed with the tool and its general architecture, we will have a more explicit idea on how to get a minimal working part inside an intel sgx enclave (the not-obvious part). This will also involve implementing/modifying the GC accordingly: Gaël will be of great help here.  Having a very simple java app running in this enclave environment will be a great step forward.
3. We could then extend the GC a little bit more to consider persistent data types. We plan to re-use sgx-romulus PM library (and other ideas) from our previous project: https://gitlab.com/Yuhala/sgx-romulus for PM related stuff.
4. With 1, 2, and 3 we could then explore point 2 in the technical objectives i.e having applications that partially execute inside enclaves via annotations etc.
5. Using the above we will then validate our approach with one of the motivating examples mentioned in the proposal (i.e Hyperledger Fabric Private Chaincode: https://github.com/hyperledger-labs/fabric-private-chaincode)
These are just tentative steps but should be a good guide as we begin.

## Update 00
* Reading papers and playing with GraalVM
