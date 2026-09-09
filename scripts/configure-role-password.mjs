import pg from "pg";

const { Client } = pg;
const ownerUrl = process.env.DIP_DEVELOPMENT_OWNER_URL;
const password = process.env.DIP_RUNTIME_PASSWORD;

if (!ownerUrl || !password) {
  throw new Error("Required in-memory provisioning variables are missing");
}

const client = new Client({ connectionString: ownerUrl });
await client.connect();
try {
  const identity = (await client.query("SELECT current_database() AS database_name, current_user AS role_name")).rows[0];
  if (identity.database_name !== "neondb" || identity.role_name !== "neondb_owner") {
    throw new Error("Refusing to configure password with an unexpected owner identity");
  }
  const quoted = (await client.query("SELECT quote_literal($1::text) AS value", [password])).rows[0].value;
  await client.query(`ALTER ROLE dip_app PASSWORD ${quoted}`);
  console.log("dip_app password configured without disclosure");
} finally {
  await client.end();
}
