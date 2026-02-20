# Secret types

APM supports **22 distinct data structures**, each with specialized fields optimized for the
type of secret being stored.

!!! note

    See the [vault management guide](../guides/vault-management.md) for an introduction to adding
    entries — this document provides a comprehensive listing of all supported types.

## Categories

When using `pm add`, you are presented with an interactive category selector. Each category has
its own set of fields tailored to the data it stores.

### Credentials

| #    | Category      | Primary Fields                   | Description                         |
| :--- | :------------ | :------------------------------- | :---------------------------------- |
| 1    | **Passwords** | Account, Username, Password, URL | Standard login credentials          |
| 2    | **TOTP**      | Account, TOTP Secret, Issuer     | Time-based one-time password seeds  |
| 3    | **API Keys**  | Service, Key, Secret, Endpoint   | REST/GraphQL API authentication     |
| 4    | **Tokens**    | Service, Token, Expiry           | Bearer tokens, refresh tokens, JWTs |

### Infrastructure

| #    | Category         | Primary Fields                           | Description                 |
| :--- | :--------------- | :--------------------------------------- | :-------------------------- |
| 5    | **SSH Keys**     | Host, Username, Private Key, Passphrase  | SSH key pairs               |
| 6    | **SSH Configs**  | Host, Port, Username, Identity File      | SSH config snippets         |
| 7    | **Cloud Creds**  | Provider, Access Key, Secret Key, Region | AWS, GCP, Azure credentials |
| 8    | **Kubernetes**   | Cluster, Namespace, Token, CA Cert       | K8s authentication secrets  |
| 9    | **Docker**       | Registry, Username, Password             | Docker registry credentials |
| 10   | **CI/CD**        | Pipeline, Provider, Token, Webhook       | CI/CD pipeline secrets      |
| 11   | **Certificates** | Domain, Certificate, Private Key, Expiry | TLS/SSL certificates        |

### Network

| #    | Category  | Primary Fields                | Description                  |
| :--- | :-------- | :---------------------------- | :--------------------------- |
| 12   | **Wi-Fi** | SSID, Password, Security Type | Wireless network credentials |

### Personal

| #    | Category           | Primary Fields                          | Description                        |
| :--- | :----------------- | :-------------------------------------- | :--------------------------------- |
| 13   | **Government IDs** | Type, Number, Issuing Authority, Expiry | Passports, driver's licenses, etc. |
| 14   | **Medical**        | Provider, Record Type, Policy Number    | Health records and insurance       |
| 15   | **Travel**         | Type, Document Number, Country, Expiry  | Visa, boarding pass, loyalty cards |
| 16   | **Contacts**       | Name, Phone, Email, Address             | Personal or professional contacts  |
| 17   | **Banking**        | Bank, Account Number, Routing, SWIFT    | Financial account details          |

### Documents

| #    | Category              | Primary Fields                      | Description                 |
| :--- | :-------------------- | :---------------------------------- | :-------------------------- |
| 18   | **Notes**             | Title, Content                      | Freeform secure text        |
| 19   | **Recovery Codes**    | Service, Codes                      | Backup recovery codes       |
| 20   | **Documents**         | Title, Content, Filename            | Secure document attachments |
| 21   | **Software Licenses** | Product, License Key, Seats, Expiry | Software license keys       |
| 22   | **Legal**             | Type, Parties, Date, Content        | Contracts, NDAs, agreements |

## Field types

Each entry, regardless of category, shares a common metadata layer:

| Field     | Description                               |
| :-------- | :---------------------------------------- |
| Name      | Display name for the entry                |
| Category  | One of the 22 categories above            |
| Namespace | Which namespace the entry belongs to      |
| Created   | Timestamp of creation                     |
| Modified  | Timestamp of last modification            |
| Tags      | Optional tags for search and organization |
| Priority  | Entry priority level                      |

## Next steps

See the [vault management guide](../guides/vault-management.md) for how to add entries, or learn
about the [policy engine](./policy-engine.md) that validates entries against security standards.
