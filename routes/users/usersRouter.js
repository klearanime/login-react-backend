var express = require('express');
var router = express.Router();
var {
  signUp,
  login,
} = require("./controller/userController")

var {
  checkIfEmptyMiddleware,
  checkForSymbolMiddleware,
  checkLoginIsEmpty,
} = require("../lib/validator")


/* GET users listing. */
router.get('/', function (req, res, next) {
  res.send('respond with a resource');
});

router.post("/sign-up",
  checkForSymbolMiddleware,
  checkIfEmptyMiddleware,
  signUp
)

router.post("/login",
  checkLoginIsEmpty,
  login
)


module.exports = router;

