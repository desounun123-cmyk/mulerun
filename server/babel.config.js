// Babel config for Jest — allows top-level `return` in CommonJS modules
// db.js uses `return` at module level to skip the SQLite section when
// DATABASE_URL is set. This is valid CommonJS but requires sourceType: 'script'.
module.exports = {
  sourceType: 'script',
  parserOpts: {
    allowReturnOutsideFunction: true,
  },
};
