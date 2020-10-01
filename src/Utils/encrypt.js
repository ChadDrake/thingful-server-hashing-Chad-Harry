const bcrypt = require("bcryptjs");

bcrypt.hash("ping-password", 12).then((hash) => console.log({ hash }));
