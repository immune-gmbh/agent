immune Guard API service
========================

This is a component of the immune Guard remote attestation product. The API
service (`apisrv`) handles everything related to the attestation and firmware
analysis. In order to avoid leaking NDA'd information the agent running on the
machine only sends raw bytes read from various parts of the platform. All
parsing and security assessments are done on the closed source service.

 - Managing registered devices and policies.
 - Enrolling devices by certifying their TPM resident keys with
   ActivateCredential.
 - Receiving TPM 2.0 Quotes, verifing their signatures and matching them
   against configured policies.
 - Apprasing TPM quotes after successful verification.
 - Notifying authsrv of new (successful or not) appraisals.
 - Parse the memory and MSR dumps from the client and produce a JSON structure
   for displaying on the frontend.

To do all that the service exposes a web API.

Build
-----

The service is written on Go and needs version 1.15 of later to be build. In
order to work the service also needs a PostgreSQL database.

Building the binary can be done with GNU Make:

```bash
make server
```

The binary is called `server`. Per default it binds on 0.0.0.0:8080 and expects
a PostgreSQL 12 database running on localhost port 5432. Starting a database
can be done with Docker. When using a fresh database the schema migrations have
to be run using a seperate tool.

```bash
make server migration
docker run --rm -p 5432:5432 -n apisrv-db -e POSTGRES_HOST_AUTH_METHOD=trust -d postgres:12

# The migration tool expects the SQL scripts to be in $(pwd)/sql
./migration -database-user postgres -database-name postgres
# The server expect the JSON schema definitions in $(pwd)/../schemas
./server

# shutdown the database
docker rm -f apisrv-db
```

### Testsuite

Running the unit tests is done by using the `-short` mode of the built Go test
suite:

```bash
go test -v -short ./...
```

Running the full test suite, including integration tests requires Docker to
start PostgreSQL databases and TPM 2.0 simulators. Make sure your docker daemon
is running and the simulator image is present. Then you can run the test suite
without the `-short` option.

```bash
docker info
docker pull immune-gmbh/simulator

go test -v ./...  # or "make test"
```

Routes
------

| Actor  | Verb   | Path                     | Payload      | Returns              |
| ---    | ---    | ---                      | ---          | ---                  |
| Webapp | GET    | `/devices?i=<iterator>`  |              | Devices              |
| Webapp | POST   | `/devices`               | Device       | Devices              |
| Webapp | GET    | `/devices/<id>`          |              | Devices              |
| Webapp | PUT    | `/devices/<id>`          | Device       | Devices, Policies    |
| Webapp | DELETE | `/devices/<id>`          |              | Devices, Policies    |
| Webapp | GET    | `/policies?i=<iterator>` |              | Policies             |
| Webapp | POST   | `/policies`              | Policy       | Policies             |
| Webapp | GET    | `/policies/<id>`         |              | Policies             |
| Webapp | PUT    | `/policies/<id>`         | Policy       | Devices, Policies    |
| Webapp | DELETE | `/policies/<id>`         |              | Devices, Policies    |
| Webapp | POST   | `/register`              | Registration | RegistrationResponse |
| Agent  | POST   | `/attest`                | Evidence     |                      |
| Agent  | POST   | `/changes`               |              | Devices, Policies    |
| Auth   | PUT    | `/customers/<id>`        |              |                      |
| Auth   | DELETE | `/customers/<id>`        |              |                      |


**`/devices`**

**`/policies`**

**`/register`**

**`/attest`**

**`/changes`**

**`/customers`**


Packages
--------

### `pkg/api`

Defines canonical structures of various immune Guard objects like devices,
policies, appraisals and so on. The mirror the JSON schema definitions in the
monorepo. The package also includes code to validate incoming strings against
the JSON schemas and.

Keep in mind the the definitions need to be kept in sync with the JSON schema.
If they diverge, the JSON schema is authoritative.

**`pkg/attestation`**

Code handling the remote attestation. It verifies incoming TPM 2.0 Quote
signatures, trys to match them against the configured policies and fills the
security report that's part of the appraisal.

**`pkg/configuration`**

**`pkg/credentials`**

**`pkg/csme`**

**`pkg/database`**

Contains the only code that directly talks to the database. We deliberatlly use
the ORM library only to fill row data into Go structs and generate simple
SELECT/INSERT statements and write SQL directly for everything else. It's is
difficult to impossible to write efficient and data race free SQL with ORMs so
we avoid it. The services uses PostgreSQL-only features like hstore and jsonb
and thus does not need to support other databases anyway.

The code includes SQL statements that go behond simple INSERT, SELECT, UPDATE,
DELETE. If you're lost check out the excellet PostgreSQL documentation. Make
sure you select version 12.

The package defines Device and Policy structures. Keep in mind that these are
different from the ones in the api packages. The ones defined mirror the
database schema and should not be used outside of the database package.

**`pkg/eventlog`**

**`pkg/firmware`**

**`pkg/key_discovery`**

The API service exposes a set of routes that are only accessible by the
authentication service. The service sends a JWT to authenticate itself. The
public key for verifying the JWT is discovered automatically using Kubernetes
annotations or Docker labels. The code to do this lives in this package.

Both implementations start a seperate Goroutine to poll the REST interface of
kubelet/docker for new keys.

**`pkg/telemetry`**

immune Guard is a distributed system. In order to make debugging possible all
services export tracing information using the Open Telemetry standard. The
telemetry package implements a thin wrapper around the OTel API.

**`pkg/tpm`**

**`pkg/web`**

Database Schema
---------------

Deployment
----------

**Config**

**Key discovery**

**External deps**

