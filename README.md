# Midpoint SCIM connector with FB workplace patches

## Build

1. Install maven
2. `mvn package -Dmaven.test.skip=true`

## Launch Midpoint

1. `docker-compose up`
2. Go to `localhost:8080/midpoint`

## Setup

1. Open `connector.xml`
2. Find `<connectorRef oid="YOUR_OID" relation="org:default" type="c:ConnectorType"/>` and replace with your connector OID (Midpoint -> Repository objects -> Connector)
3. Import `roles.xml` and `tasks.xml` files via Midpoint
4. Go to `Midpoint -> Resources -> Workplace SCIM connector -> Edit configuration` and enter `Token` (Access token from FB API) 

## Logs

Logs are located at `/opt/midpoint/var/log/midpoint.log`

To improve verbosity of SCIM connector logs - Midpoint -> System -> Logging -> Add `com.evolveum.polygon.scim.WorkplaceHandlingStrategy` `ALL`

# Other

Midpoint default credentials - administrator / 5ecr3t

[Connector development guide](https://wiki.evolveum.com/display/midPoint/Connector+Development+Guide)

[Workplace SCIM docs](https://developers.facebook.com/docs/workplace/account-management/api/)

[Workplace Graph API docs](https://developers.facebook.com/docs/workplace/reference/graph-api/)

Test workplace - https://workplace.facebook.com/

To get community ID visit https://graph.facebook.com/community?access_token={access_token}