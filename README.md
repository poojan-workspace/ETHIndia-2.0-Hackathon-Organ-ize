# Organ-ize: A Proxy Re-Encryption Scheme Based Organ Donation Application

## Organ-ize Publication
#### https://drive.google.com/file/d/1xfV38hV3lrzOBaYUsF05urprv0eRTA_f/view?usp=share_link

## ETHIndia 2.0 Hackathon 3rd Place Winner
#### https://devfolio.co/projects/organize
#### https://ethindia2019.devfolio.co/projects?tracks=NuCypher

## Elevator Pitch
#### “To secure the organ donor’s medical records using data encryption until his/her demise and then delegate access to concerned authorities using NuCypher’s PRE (Proxy Re-Encryption) network.”

## The application focuses mainly on 4 major qualities:
1. The anonymity of the organ donor should be maintained in the network.
2. Privacy and Security of an organ donor’s medical records.
3. Confidentiality of an organ donor’s private medical data.
4. Keeping a track of unethical practices(organ trafficking) in the network.

## Basic Scenario
Let’s say, Alice wants to donate her organs after her demise. She collects all the necessary documents like Identity Proofs, Medical check-ups, Official Organ Donation documents, etc and encrypts the data using her private key P(A), and then encrypted data will be uploaded on IPFS storage. Using NuCypher’s Policy Protocol, Alice will be able to write a policy statement granting access to all the medical data related to organ donation to a Medical Institution. Alice’s Identity will always remain anonymous in the network. 

Using Shamir’s Secret Sharing Scheme, Alice will divide her private key P(A) into 2 sub-keys P(A1) and P(A2) and hand it over to her trustees, Bob and Carol. So that after Alice&#39;s death, Bob and Carol together can take charge of the medical documents and grant access for Alice’s data to a Medical Institution so that all the procedures of organ transplant can be executed on time (before the body starts decomposing). And also Bob and Carol cannot individually access/tamper Alice’s data using sub-keys. So Secret Sharing solves the problem of data tampering after Alice's death.

![Organ-ize](https://user-images.githubusercontent.com/115387678/198776324-373bc9b6-4ee9-4605-b21a-5ecbe8360a96.PNG)

## Tools and Technologies:
NuCypher's Threshold Proxy Re-Encryption Scheme (Umbral), Shamir's Secret Sharing Scheme (SSSS), The InterPlanetary File System (IPFS), Flask.

## Web Application:
#### 1. Generation of Private and Public Keys
![image](https://user-images.githubusercontent.com/115387678/198778701-43f54f67-a9f1-468a-bef0-7bd97e3d99b6.png)

#### 2. Data Encrypted using Owner’s Public Key
![image](https://user-images.githubusercontent.com/115387678/198778923-67471c80-58f4-4c9d-b8a4-73bff015a353.png)

#### 3. Threshold value and Number of Shares
![image](https://user-images.githubusercontent.com/115387678/198779017-3a6fde9b-7e89-40ce-ba7a-73269e4e96b5.png)

#### 4. Alice’s Private Key Splitted using SSSS
![image](https://user-images.githubusercontent.com/115387678/198779119-9304ec27-9758-4a3c-8d54-ccd5288eb146.png)

#### 5. Combining the Shares to generate the original Private Key
![image](https://user-images.githubusercontent.com/115387678/198779222-ffd92199-8129-4c9d-9144-160406641561.png)

#### 6. Original Private Key Generated after combining the shares
![image](https://user-images.githubusercontent.com/115387678/198779341-11725eab-4d37-41b9-9915-6ffc92879924.png)

#### 7. Re-encryption of Alice’s Secret Data using Hospital’s Public Key
![image](https://user-images.githubusercontent.com/115387678/198779448-884e08f5-2bb5-4483-a9ac-3465286e90bd.png)

#### 8. De-encrypt the Secret Data using Hospital’s Private key
![image](https://user-images.githubusercontent.com/115387678/198779592-d10ef126-fd5c-4a15-a1a2-488bfdda5016.png)
