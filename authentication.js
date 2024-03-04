const express = require("express");
const path = require("path");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
//use this to activate the nodemon
//powershell -ExecutionPolicy Bypass -Command "nodemon app.js"
const dbPath = path.join(__dirname, "userData.db");
const apps = express();
apps.use(express.json());

let db = null;

const initDBandServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    apps.listen(3000, () => {
      console.log(`Server is running at http://localhost:3000`);
    });
  } catch (e) {
    console.log(`Error ${e.message}`);
  }
};
initDBandServer();

//Getting the user

apps.get("/getting", async (request, response) => {
  let jwtToken;
  const authheader = request.headers["authorization"];
  if (authheader !== undefined) {
    jwtToken = authheader.split(" ")[1];
    jwt.verify(jwtToken, "Secret_code", async (error, payload) => {
      if (error) {
        response.send("Error Token code");
      } else {
        const userDetailQuerry = `
        SELECT * FROM user
        `;
        const userDetail = await db.all(userDetailQuerry);
        response.send(userDetail);
      }
    });
  }
  else{
    response.status = 400
    response.send("Error")
  }
});

//Register the New User

apps.post("/register/", async (request, response) => {
  const { username, name, password, gender, location } = request.body;
  const hashedPassword = await bcrypt.hash(request.body.password, 10);
  const usernamefind = `SELECT * FROM user WHERE username =?`;

  const dbUsername = await db.get(usernamefind, [username]);
  if (dbUsername === undefined) {
    if (password.length < 5) {
      response.status = 400;
      response.send("Password is too small");
    } else {
      const addQuerry = `
            INSERT INTO user (username, name, password, gender, location)
            VALUES( '${username}', '${name}', '${hashedPassword}', '${gender}', '${location}');

            `;
      const dbuser = await db.run(addQuerry);
      const newUser = dbuser.lastId;
      response.send("Account Created Successfuly");
    }
  } else {
    response.status = 400;
    response.send("User already exist");
  }
});

//login

apps.post("/login", async (request, response) => {
  const { username, password } = request.body;
  const dbUsername = ` SELECT * FROM user WHERE username = ?`;

  const dbUser = await db.get(dbUsername, [username]);
  console.log(dbUser);
  if (!dbUser) {
    response.status = 400;
    response.send("Username does not Exist");
  } else {
    const isPassmatched = await bcrypt.compare(password, dbUser.password);
    if (isPassmatched === true) {
      const payload = {
        username: username,
      };
      const jwtToken = jwt.sign(payload, "Secret_code");
      response.send(`Jwttoken : ${jwtToken}`);
    } else {
      response.status = 400;
      response.send("Password Incorrect");
    }
  }
});

apps.put("/change-password", async (request, response) => {
  const { username, oldPassword, newPassword } = request.body;
  const dbUsername = `SELECT * FROM user WHERE username = ?`;

  const dbUsernameGet = await db.get(dbUsername, [username]);
  const prevPassword = await bcrypt.compare(
    oldPassword,
    dbUsernameGet.password
  );
  const encPass = await bcrypt.hash(newPassword, 10);

  if (prevPassword === true) {
    if (newPassword < 5) {
      response.status = 400;
      response.send("Password is too short");
    } else {
      const updating = ` UPDATE user
      SET password = ?
      WHERE username = ?;
    `;
      await db.run(updating, [encPass, username]);
      response.send("Password updated");
    }
  } else {
    response.status = 400;
    response.send("Invalid current password");
  }
});

apps.delete("/register/:username", async (request, response) => {
  const { username } = request.params;
  const deleteUser = `
    DELETE FROM user WHERE username = ?
    `;

  const sendRequest = await db.run(deleteUser, [username]);
  response.send("Deleted Successfully");
});
