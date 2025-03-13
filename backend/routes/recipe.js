const express = require('express');
const { getRecipes, getRecipe, addRecipes, editRecipes, deleteRecipes  } = require('../controller/recipe');
const router = express.Router();

router.get('/', getRecipes);
router.get('/:id', getRecipe);
router.post('/', addRecipes);
router.put('/:id', editRecipes);
router.delete('/:id', deleteRecipes);

module.exports = router;