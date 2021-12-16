const createUserToken = (user) => {
  return { name: user.name, userID: user._id, role: user.role }
}

module.exports = {
  createUserToken,
}
