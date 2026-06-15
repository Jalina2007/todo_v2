import ballerina/http;
import ballerina/sql;
import ballerina/jwt;
import ballerinax/mysql;
import ballerinax/mysql.driver as _;

configurable string dbHost = "localhost";
configurable int dbPort = 3306;
configurable string dbUser = "root";
configurable string dbPassword = ?;
configurable string dbName = "tododb";
configurable int serverPort = 9090;

// Asgardeo (WSO2) token validation settings.
// issuer:   https://api.asgardeo.io/t/<org>/oauth2/token
// audience: your application's Client ID
// jwksUrl:  https://api.asgardeo.io/t/<org>/oauth2/jwks
configurable string jwtIssuer = ?;
configurable string jwtAudience = ?;
configurable string jwksUrl = ?;

final mysql:Client db = check new (
    host = dbHost,
    port = dbPort,
    user = dbUser,
    password = dbPassword,
    database = dbName
);

type Todo record {|
    int id?;
    string name;
    string description;
    string? end_date;
    boolean completed;
|};

type User record {|
    int id;
    string sub;
|};

@http:ServiceConfig {
    cors: {
        allowOrigins: ["http://localhost:5173"],
        allowHeaders: ["Authorization", "Content-Type"],
        allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    }
}
service /api on new http:Listener(serverPort) {

    resource function get todos(http:Request req) returns Todo[]|http:Unauthorized|error {
        string|error sub = extractSub(req);
        if sub is error {
            return http:UNAUTHORIZED;
        }
        int userId = check getOrCreateUser(sub);
        stream<Todo, sql:Error?> resultStream = db->query(
            `SELECT id, name, description, end_date, completed
             FROM todos WHERE user_id = ${userId} ORDER BY created_at DESC`
        );
        Todo[] todos = check from var row in resultStream select row;
        return todos;
    }

    resource function post todos(http:Request req, @http:Payload Todo todo) returns Todo|http:Unauthorized|error {
        string|error sub = extractSub(req);
        if sub is error {
            return http:UNAUTHORIZED;
        }
        int userId = check getOrCreateUser(sub);
        sql:ExecutionResult result = check db->execute(
            `INSERT INTO todos (user_id, name, description, end_date, completed)
             VALUES (${userId}, ${todo.name}, ${todo.description}, ${todo.end_date}, ${todo.completed})`
        );
        todo.id = <int>result.lastInsertId;
        return todo;
    }

    resource function put todos/[int id](http:Request req, @http:Payload Todo todo) returns Todo|http:Unauthorized|http:NotFound|error {
        string|error sub = extractSub(req);
        if sub is error {
            return http:UNAUTHORIZED;
        }
        int userId = check getOrCreateUser(sub);
        sql:ExecutionResult result = check db->execute(
            `UPDATE todos SET name = ${todo.name}, description = ${todo.description},
             end_date = ${todo.end_date}, completed = ${todo.completed}
             WHERE id = ${id} AND user_id = ${userId}`
        );
        if result.affectedRowCount == 0 {
            return http:NOT_FOUND;
        }
        todo.id = id;
        return todo;
    }

    resource function delete todos/[int id](http:Request req) returns http:Ok|http:Unauthorized|http:NotFound|error {
        string|error sub = extractSub(req);
        if sub is error {
            return http:UNAUTHORIZED;
        }
        int userId = check getOrCreateUser(sub);
        sql:ExecutionResult result = check db->execute(
            `DELETE FROM todos WHERE id = ${id} AND user_id = ${userId}`
        );
        if result.affectedRowCount == 0 {
            return http:NOT_FOUND;
        }
        return http:OK;
    }
}

final jwt:ValidatorConfig jwtValidatorConfig = {
    issuer: jwtIssuer,
    audience: jwtAudience,
    signatureConfig: {
        jwksConfig: {
            url: jwksUrl
        }
    }
};

function extractSub(http:Request req) returns string|error {
    string authHeader = check req.getHeader("Authorization");
    string token = re `Bearer `.replaceAll(authHeader, "");
    jwt:Payload payload = check jwt:validate(token, jwtValidatorConfig);
    return payload.sub ?: error("No sub claim in token");
}

function getOrCreateUser(string sub) returns int|error {
    User|error existing = db->queryRow(
        `SELECT id, sub FROM users WHERE sub = ${sub}`
    );
    if existing is User {
        return existing.id;
    }
    sql:ExecutionResult result = check db->execute(
        `INSERT INTO users (sub) VALUES (${sub})`
    );
    return <int>result.lastInsertId;
}