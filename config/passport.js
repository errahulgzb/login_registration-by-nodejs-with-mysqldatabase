var LocalStrategy= require("passport-local").Strategy;
var mysql= require("mysql");
var bcrypt= require("bcrypt-nodejs");
var dbconfig= require("./database");
var connection= mysql.createConnection(dbconfig.connection);
connection.query("USE",+dbconfig.database);
module.exports=function(passport){
	passport.serializeUser(function(user,done){
		done(null,user.id);
	});
	passport.deserializeUser(function(id,done){
		connection.query("SELECT * FROM users WHERE id=?",[id],function(err,rows){
			done(err,rows[0]);
		});
	});

	passport.use("local-signup",
		new LocalStrategy({
			usernameField:'username',
			passwordField:'password',
			passReqToCallback:true

		}),
		function(req,username,password,done){
			connection.query("SELECT * FROM users WHERE username=?",[username],function(err,rows){
				if(err){
					done(err);
				}
				if(rows.length){
					return done(null,false,req.flash('signupMessage','Username already exists, Please try another username.'));
				}else{
					var newUserMysql= {
						username:username,
						password:bcrypt.hashSync(password,null)
					};

					var insertQuery="INSERT INTO users (username,password) values (?,?)";
					connection.query(insertQuery,[newUserMysql.username,newUserMysql.password],
						function(err,rows){
							newUserMysql.id=rows.insertId;
							return done(null,newUserMysql);
						});
				}
			});
		});

	passport.use(new LocalStrategy({
			usernameField:"username",
			passwordField:"password",
			passReqToCallback:true
		},
		function(req,username,password,done){
			connection.query("SELECT * FROM users WHERE username=?",[username],function(err,rows){
					if(err){
						return done(err);
					}
					if(!rows.length){
						return done(null,false,req.flash("loginMessage","No user found!!."));
					}
					if(!bcrypt.compareSync(password,rows[0].password)){
						return done(null,rows[0]);
					}
				});
		}));

};