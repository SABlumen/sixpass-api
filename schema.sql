drop table if exists user;
CREATE TABLE user(
    "id" INTEGER PRIMARY KEY,
    "email" TEXT UNIQUE NOT NULL,
    "password" TEXT NOT NULL,
    "salt" BLOB UNIQUE NOT NULL
);
drop table if exists password;
CREATE TABLE password(
    "id" INTEGER PRIMARY KEY,
    "user_id" INTEGER NOT NULL,
    "title" TEXT UNIQUE,
    "url" TEXT NOT NULL,
    "username" TEXT,
    "password" BLOB,
    "note" TEXT,
    "created" DATETIME NOT NULL,
    "accessed" DATETIME,
    "modified" DATETIME,
    FOREIGN KEY ("user_id")
        REFERENCES user ("id")
);
drop table if exists label;
CREATE TABLE label(
    "id" INTEGER PRIMARY KEY,
    "user_id" INTEGER NOT NULL,
    "name" TEXT,
    FOREIGN KEY ("user_id")
        REFERENCES user ("id")
);
drop table if exists association;
CREATE TABLE association(
    "label_id" INTEGER NOT NULL REFERENCES label(id),
    "password_id" INTEGER NOT NULL REFERENCES password(id),
    PRIMARY KEY (label_id, password_id)
);
