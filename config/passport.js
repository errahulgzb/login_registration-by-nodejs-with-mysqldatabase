var LocalStrategy= require("passport-local").Strategy;
var mysql= require("mysql");
var bcrypt= require("bcrypt-nodejs");
var dbconfig= require("./database");
var connection= mysql.creationConnection();