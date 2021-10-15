#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# FLARE-ON 2021: 10 - Wizardcult
# ----------------------------------------------------------------------------------------
wizardcult_tables_Ingredients = [
    'bone', 'undead eyeball', 'spider', 'fish tail', 'adamantine',
    'tentacle of giant octopus or giant squid', 'ice', 'coal', 'food morsel',
    'bitumen (a drop)', 'giant slug bile', 'jade dust', 'rotten egg',
    'silver powder', 'artistic representation of caster', 'oils and unguents',
    'soil mixture in a small bag', 'gem-encrusted bowl', 'magic item', 'makeup',
    'talcum powder', 'black silk square', 'licorice root shaving', 'tears',
    'salt', 'dirt', 'silver mirror', 'wire of fine silver',
    'parchment with holy word written upon it', 'gauze', 'bone dust', 'dust',
    'quartz', 'lodestone', 'sponge', 'rope', 'shamrock', 'firefly', 'iron',
    'soot', 'forked twig', 'distilled spirits', 'mercury', 'opaque glass',
    'marked sticks or bones', 'ink', 'niter', 'corn', 'hot pepper', 'pebble',
    'stone', 'wychwood', 'miniature hand sculpted from clay', 'amber',
    'brimstone', 'pickled tentacle', 'jade circlet',
    'sacrificial offering appropriate to deity', 'fur of bloodhound',
    'jeweled horn', 'lime', 'vessel to contain a medium-sized creature',
    'cloth wad', 'stem of a thorny plant', 'pitch',
    'chalks and inks infused with precious gems', 'tallow', 'silk square',
    'earth', 'molasses (a drop)', 'feldspar', 'jewel', 'mandrake root', 'focus',
    'eyeball', 'silver bar', 'fur', 'glass sliver', 'ivory portal (miniature)',
    'crystal bead', 'ash', 'sand', 'feather of owl', 'tuft of fur',
    'ink lead-based', "feather from any bird's wing", 'mistletoe',
    'chrysolite powder', 'lead', 'phosphorescent moss', 'blood', 'quiver',
    'ointment for the eyes', 'butter', 'wisp of smoke', 'magnifying glass',
    'incense', 'honeycomb', 'spiderweb', 'snaketongue', 'humanoid blood',
    'herbs', 'string', 'rose petals', 'gilded skull', 'pearl', 'obsidian',
    'sweet oil', 'twig from a tree that has been struck by lightning',
    'phosphorus', 'polished marble stone', 'gold-inlaid vial', 'gum arabic',
    'twig', 'silver rod', 'fur of bat', 'mistletoe sprig',
    'an item distasteful to the target', 'moonseeds', 'iron blade', 'rock chip',
    'sumac leaf', 'fleece', 'sunstone', 'granite',
    'quill plucked from a sleeping bird', 'diamond', 'bell (tiny)', 'thorns',
    'silver spoon', 'tarts', "adder's stomach", 'reed',
    'jewel-encrusted dagger', 'caterpillar cocoon', 'clay pot of grave dirt',
    'gem as powder', 'iron filings or powder', 'flesh',
    'tiny piece of target matter', 'ammunition', 'clay and water', 'sulfur',
    'black pearl (as crushed powder)', 'ruby (as dust)', 'gilded acorn',
    'leather loop', 'cloak', 'spheres of glass', 'cured leather',
    'snakeskin glove', 'alum soaked in vinegar', 'cork', 'crystal sphere',
    'flame', 'eggshells', 'silver cage', 'prayer wheel', 'copper piece',
    'crystal vial of phosphorescent material', 'feather of hummingbird',
    "red dragon's scale", 'forked metal rod', 'snow', 'eggshell',
    'engraving of symbol of the outer planes', 'black onyx stone',
    'petrified eye of newt', 'silver whistle', 'charcoal', 'hand mirror',
    'lockbox of ornate stone and metal', 'glass eye', 'silver and iron',
    'glass or crystal bead', 'rotten food', 'clay model of a ziggurat',
    'diamond and opal', 'skunk cabbage leaves', 'ashes of mistletoe and spruce',
    'nut shells', 'statue of the caster', 'exquisite chest', 'clay', 'thread',
    "hen's heart", 'knotted string', 'rhubarb leaf', 'sesame seeds', 'ruby',
    "grasshopper's hind leg", 'ivory strips', 'paper or leaf funnel',
    'oak bark', 'crystal or glass cone', 'water', 'agate', 'holy water',
    'mica chip', 'weapon', 'club', 'bull hairs',
    'reliquary containing a sacred relic', 'crystal hemisphere', 'holly berry',
    'divinatory tools', 'yew leaf', 'gum arabic hemisphere',
    'eyelash in gum arabic', 'leather strap', 'silver pins', 'platinum sword',
    'legume seed', 'detritus from the target creature', 'copper wire',
    'gilded flower', 'guano', 'artistic representation of target',
    'flea (living)', 'cricket', 'oil', 'parchment as a twisted loop',
    'glowworm', 'golden reliquary', 'umber hulk blood', 'jacinth',
    'holy symbol', 'graveyard dirt (just a pinch)', 'wood',
    'fur wrapped in cloth', 'honey drop', 'platinum-inlaid vial', 'fan',
    'straw', 'sapphire', 'sunburst pendant', 'green plant', 'golden wire',
    'clay pot of brackish water', 'platinum rings', 'air', 'colored sand ',
    'gem or other ornamental container', 'sugar', 'holy/unholy water',
    'gold dust', 'copper pieces', 'pork rind or other fat', 'silver rings',
    'pickled octopus tentacle', 'gem', 'dried carrot', 'melee weapon',
    'feather', 'ruby vial', 'kernels of grain'
]

wizardcult_tables_DungeonDescriptions = [
    'peculiar', 'wee', 'countless', 'foul', 'down various', 'petal',
    'dark and horrible', 'evil', 'unhealthy subterranean', 'large',
    'great hopeless', 'miniature', 'nearby', 'airless', 'spiritual',
    'gloomy and awful', 'inexorable', 'pestilent', 'prospective', 'certain',
    'dark dank', 'dour', 'detestable', 'khronal', 'dark and mysterious',
    'appalling', 'movable', 'professional', 'rockbound', 'slimy dark',
    'dark and solitary', 'mute', 'danish', 'walled', 'hideous', 'dank dark',
    'pure', 'dire', 'totalitarian', 'sombre', 'eternal', 'senseless internal',
    'ancient', 'drafty', 'painful', 'dark and pestilential', 'cruel', 'flimsy',
    'horribly dirty', 'dumb', 'dark and dreary', 'grievous', 'devilish little',
    'deep and dark', 'moral', 'arched', 'empty', 'wooden', 'dismal underground',
    'genuine', 'sticky', 'central', 'decayed', 'fairly cozy', 'dirty',
    'dismal old', 'unwholesome', 'largely ceremonial', 'magnificent', 'oldest',
    'dangerous', 'horrid gloomy', 'first-floor', 'cleanest', 'inaccessible',
    'yon dark', 'whole', 'rusty', 'nice', 'horrid', 'utterly black', 'fetid',
    'minor', 'darkest', 'dark and deep', 'ould', 'dark and gloomy',
    'more decent', 'historical', 'infamous', 'exceedingly dirty and dark',
    'oppressive', 'lousy', 'historic', 'separate', 'last', 'grimmest',
    'dark oppressive', 'foul and loathsome', 'dark and gruesome',
    'deep subterranean', 'average', 'many gloomy', 'bad', 'drowsy', 'nicest',
    'miraculous', 'ominous', 'frightening', 'gruesome great', 'common',
    'inhospitable', 'damned', 'real', 'few dismal', 'virtual', 'more strange',
    'same dreary', 'lower-level', 'slimy', 'royal', 'salty', 'solid',
    'cathedral', 'siberian', 'real old-fashioned', 'gilded', 'underground',
    'condemned-criminal', 'great', 'dark little', 'cloudy',
    'unknown and inaccessible', 'soundproof', 'sinister', 'unseen', 'penal',
    'gray', 'wiry', 'warm airless', 'italian', 'moist and dirty', 'fiery',
    'dear old', 'best', 'unsavory', 'weary', 'infinite',
    'terrible subterranean', 'great and horrible', 'more comfortable',
    'dark narrow', 'humid', 'foul and filthy', 'familiar',
    'small and loathsome', 'festive', 'fairly extensive', 'intimate',
    'bottomless', 'endless', 'late', 'industrial', 'heavy', 'fourth', 'safe',
    'awful', 'livable', 'indecent and disgusting', 'old', 'imperial',
    'deep dark', 'lowest', 'great dark', 'dark and humid', 'dark deep', 'lone',
    'cavernous', 'european', 'grim old', 'macabre', 'egyptian', 'special',
    'convenient', 'right-hand', 'episcopal', 'cramped little', 'cool',
    'disagreeable', 'turkish', 'provincial', 'almost magical', 'more gloomy',
    'dreary', 'gloomy little', 'lowest and foulest', 'silent', 'dank',
    'rugged and decayed', 'draconian', 'dark and dismal', 'conventional',
    'worst', 'fake', 'foul-smelling', 'awful old', 'traditional', 'polish',
    'warm', 'dark', 'black and noxious', 'strong', 'morbid',
    'perfectly satisfactory', 'entire', 'high', 'true', 'official', 'rbital',
    'southern', 'red hot', 'single', 'cold and gloomy', 'natural', 'subsequent',
    'african', 'now empty', 'magical', 'proper', 'almost impenetrable',
    'underwater', 'rocky', 'kindest', 'creepy', 'upper', 'roomier', 'open',
    'remote and inaccessible', 'smoky', 'unused', 'fatal', 'entire vast',
    'visionary', 'brazen', 'popular', 'automatic', 'narrow and filthy', 'next',
    'particularly unpleasant', 'papal', 'dark and sombre', 'dark underground',
    'dreary and dismal', 'unexplored', 'narrow underground',
    'mysterious subterranean', 'profound', 'dark and pestilent', 'makeshift',
    'still dark', 'secret underground', 'double', 'deathly cold', 'murky',
    'high-tech', 'memorable', 'terrible', 'thy great', 'dark and evil',
    'fearful', 'cramped', 'famous', 'three-room', 'canadian', 'hypothetical',
    'run-of-the-mill', 'nasty', 'authentic', 'uncomfortable', 'unknown',
    'strongest', 'unspeakable', 'colonial', 'nauseous', 'claustrophobic',
    'dreadful little', 'academic', 'dark and loathsome', 'vacant', 'spacious',
    'similar', 'far-off', 'own little', 'cosy', 'inner', 'more ordinary',
    'deeper', 'draughty', 'little inner', 'more wretched', 'superior', 'wintry',
    'luxurious', 'spanish', 'mere', 'doleful', 'deep', 'criminal', 'rich',
    'more-than-physical', 'vile', 'low dark', 'ideal', 'bare', 'wide',
    'antique', 'literary', 'deep old', 'dark cold', 'delightful', 'british',
    'pallid', 'squalid', 'orbital', 'afghan', 'blood-flecked', 'illusory',
    'stark white', 'indecent', 'sure', 'deepest and most loathsome',
    'old-fashioned', 'dismal subterranean', 'suitable', 'hopeless secret',
    'mental', 'dirty little', 'complete', 'horrible', 'dark and unwholesome',
    'scanty', 'notorious', 'gaudy', 'first-class', 'gloomy', 'windowless',
    'simple', 'subterranean', 'silky', 'torrid', 'terribly dark',
    'deep and gloomy', 'own private', 'problematical', 'high-class', 'dreadful',
    'shadowy', 'dark foul', 'watery', 'hardcore', 'indestructible', 'enormous',
    'foul subterranean', 'still deeper', 'alien', 'unfathomable', 'elegant',
    'dusky', 'syrian', 'dank and miserable', 'various', 'dreary red-brick',
    'dank and gloomy', 'sombre and almost magical', 'long', 'snug',
    'fatally deep', 'hollow', 'filthy and loathsome', 'immense', 'ceremonial',
    'surprisingly clean', 'unhealthy', 'crystal', 'strange subterranean',
    'open-air', 'dingy', 'now distant', 'numerous', 'sacrificial',
    'miserable old', 'pestilential', 'more safe', 'modern', 'excellent',
    'marvelous', 'loathsome and unwholesome', 'old underground', 'so-called',
    'effective', 'inquisitional', 'thy dim', 'secret', 'formidable', 'concrete',
    'top-selling', 'antiquated', 'dark solitary', 'perpetual', 'fantastic',
    'austrian', 'large empty', 'massive', 'normal', 'same ominous',
    'infectious', 'darker', 'mexican', 'antiseptic', 'rankest', 'impressive',
    'great and little', 'ecclesiastical', 'current', 'obscure', 'lower',
    'common criminal', 'sundry dark', 'fetid underground', 'sadistic',
    'foreign', 'abominable', 'horrible little', 'several dark', 'dim',
    'awe-inspiring', 'agreeable', 'narrow', 'earthy', 'bomb-proof', 'jewish',
    'icebound', 'shallow', 'forlorn', 'past', 'strong and deep', 'former',
    'old secret', 'archaic', 'veritable', 'well-equipped', 'more terrible',
    'more roomy', 'stony', 'perfect', 'mighty', 'lifelong', 'absolute',
    'decent', 'beetling', 'handy', 'chaotic', 'best modern',
    'bare and miserable', 'dark and fetid', 'respective', 'rollicking',
    'infernal', 'chief', 'cold and dark', 'odd', 'gloomier', 'tropical',
    'world-wide', 'more dangerous', 'cold gray', 'deepest and strongest',
    'unpleasant', 'more infernal', 'villainous', 'literal', 'capacious',
    'cozy little', 'gruesome', 'more dreary', 'uneasy', 'disused', 'clean',
    'barbaric', 'sumptuous', 'sad', 'dreary old', 'swedish', 'coral', 'wet',
    'present', 'feudal', 'foul underground', 'private', 'closer', 'imperial',
    'frightful', 'small', 'many terrible', 'dank little', 'cold', 'circular',
    'ancient subterranean', 'blackest', 'black and dismal', 'miserable',
    'wretched little', 'monastic', 'dark and inscrutable', 'grotesque',
    'deepest and darkest', 'wretched', 'little', 'dull', 'principal',
    'same dank', 'french', 'miserably dark', 'old filthy', 'everlasting',
    'physical', 'charmingly horrible', 'impenetrable', 'mysterious',
    'nice deep', 'hot', 'clammy', 'perfectly normal', 'correctional',
    'disgusting', 'dirtiest', 'darkest and deepest', 'black rollicking',
    'gloomy academic', 'monstrous', 'stuffy', 'bloodstained', 'triple',
    'irksome', 'moist', 'cold and humid', 'satisfactory', 'inquisitorial',
    'last-mentioned', 'roomy', 'remotest', 'frigid', 'intangible', 'black',
    'internal', 'usual', 'tubular', 'own dark', 'loathsome and lousy',
    'third-floor', 'safest', 'easy', 'inscrutable', 'outer',
    'dark and miserable', 'strange', 'full', 'noxious', 'narrow gloomy',
    'unsuspected', 'dark and fearful', 'queer', 'ancestral', 'emotional',
    'narrower', 'fifth', 'military', 'mammoth', 'dark and filthy', 'original',
    'rugged', 'strange and secret', 'great old', 'unnumbered', 'own peculiar',
    'heretical', 'more frightening', 'deepest darkest', 'horrible dark',
    'remote', 'damn', 'immense and frightful', 'pagan', 'invisible', 'shameful',
    'online', 'thy dark', 'rectangular', 'grimy', 'airy', 'red-brick',
    'classical', 'eastern', 'grand', 'dreary subterranean', 'great and secret',
    'bleak', 'dark loathsome', 'dusty old', 'differential', 'mad',
    'unfortunately dank and cold', 'horrid little', 'partially open-air',
    'revolting', 'gloomy underground', 'vast', 'last and lowest', 'white',
    'big', 'great central', 'political', 'fine', 'chinese', 'domestic',
    'contiguous', 'more filthy', 'twentieth-century', 'distant',
    'filthy and dark', 'nice little', 'public', 'blind', 'also subterranean',
    'second-floor', 'good', 'dismal', 'filthy', 'black lower', 'dusty',
    'standard', 'bloody', 'moldy', 'loathsome underground', 'extensive',
    'loathsome and unhealthy', 'gorgeous', 'worse', 'further', 'large and dark',
    'dark and narrow', 'slippery', 'unfortunately dank', 'mock', 'hateful',
    'few old', 'dark and horribly dirty', 'cold subterranean', 'horrid old',
    'local', 'inconvenient', 'biggest', 'dark hot', 'same old', 'hopeless',
    'green', 'lonesome', 'fiendish', 'fabled', 'intact', 'leaky',
    'dark and hideous', 'dreadful dark', 'aerial', 'dim and gloomy', 'moorish',
    'olden ducal', 'dark dismal', 'sordid', 'breathless', 'temporary', 'thick',
    'loathsome inner', 'foul and obscure', 'wrong', 'loathsome detestable',
    'less historic', 'dirty and dark', 'general', 'charming', 'menacing',
    'thy gloomy', 'fine little', 'babylonian', 'far worse', 'fragrant',
    'goddamned', 'huge', 'civilized', 'faint', 'undecorated', 'dark monastic',
    'solitary', 'dark and silent', 'federal', 'personal',
    'sordid and miraculous', 'ancient feudal', 'vast and deep', 'loathsome',
    'comfortable', 'deepest', 'dark and dank', 'different', 'exceedingly dirty',
    'low', 'dark and foul', 'main', 'cozy', 'adjacent', 'foul and dismal',
    'ducal', 'life-long', 'theroyal', 'nearest', 'ordinary', 'legendary',
    'gloomy and impenetrable', 'particular', 'actual', 'foulest',
    'hideous and dirtiest', 'curious', 'inexplicable', 'imaginary',
    'little cramped', 'icy', 'hideous little', 'high-rise', 'quiet', 'lost',
    'grim', 'german', 'utter'
]

potion_1 = ("magnifying glass, kernels of grain, silver spoon, fish tail, "
            "undead eyeball, undead eyeball, coal, ash, silver rod, gold-inlaid"
            " vial, rose petals, silver rod, honeycomb, phosphorus, undead "
            "eyeball, kernels of grain, tarts, bone, undead eyeball, coal, "
            "undead eyeball, tentacle of giant octopus or giant squid, glass "
            "sliver, honeycomb, rose petals, pearl, snaketongue, undead "
            "eyeball, adamantine, bone, undead eyeball, tentacle of giant "
            "octopus or giant squid, focus, polished marble stone, gum arabic, "
            "an item distasteful to the target, mistletoe sprig, undead "
            "eyeball, kernels of grain, reed, bone, undead eyeball, ice, "
            "crystal bead, an item distasteful to the target, mistletoe sprig, "
            "gum arabic, an item distasteful to the target, mistletoe sprig, "
            "undead eyeball, kernels of grain, caterpillar cocoon, bone, undead"
            " eyeball, adamantine, silk square, gum arabic, an item distasteful"
            " to the target, fur of bat, undead eyeball, kernels of grain, "
            "sulfur, bone, undead eyeball, adamantine, feather of owl, crystal "
            "bead, glass sliver, fur of bat, undead eyeball, kernels of grain, "
            "spheres of glass, bone, undead eyeball, adamantine, feather of "
            "owl, chalks and inks infused with precious gems, glass sliver, fur"
            " of bat, undead eyeball, kernels of grain, cork, bone, undead "
            "eyeball, tentacle of giant octopus or giant squid, fur, pearl, "
            "polished marble stone, sweet oil, fur of bat, undead eyeball, "
            "kernels of grain, silver cage, bone, bone, bone, sponge, kernels "
            "of grain, adder's stomach, fish tail, undead eyeball, undead "
            "eyeball, jade dust, focus, polished marble stone, gum arabic, an "
            "item distasteful to the target, mistletoe sprig, earth, herbs, "
            "moonseeds, pearl, snaketongue, herbs, undead eyeball, kernels of "
            "grain, reed, bone, undead eyeball, undead eyeball, undead eyeball,"
            " adamantine, ivory portal (miniature), honeycomb, phosphorus, "
            "herbs, undead eyeball, rotten egg, bone, bone, bone, rope, kernels"
            " of grain, jewel-encrusted dagger, fish tail, undead eyeball, "
            "undead eyeball, rotten egg, crystal bead, an item distasteful to "
            "the target, mistletoe sprig, gum arabic, an item distasteful to "
            "the target, mistletoe sprig, earth, herbs, moonseeds, pearl, "
            "snaketongue, herbs, undead eyeball, kernels of grain, caterpillar "
            "cocoon, bone, undead eyeball, undead eyeball, undead eyeball, "
            "adamantine, ivory portal (miniature), honeycomb, phosphorus, "
            "herbs, undead eyeball, rotten egg, bone, bone, bone, tears, "
            "kernels of grain, clay and water, spider, undead eyeball, undead "
            "eyeball, food morsel, quiver, butter, moonseeds, phosphorus, "
            "niter, silk square, gum arabic, an item distasteful to the target,"
            " undead eyeball, kernels of grain, sulfur, bone, undead eyeball, "
            "kernels of grain, gem as powder, bone, bone, silk square, kernels "
            "of grain, clay pot of grave dirt, fish tail, undead eyeball, "
            "undead eyeball, fish tail, silk square, gum arabic, an item "
            "distasteful to the target, undead eyeball, kernels of grain, gem "
            "as powder, bone, undead eyeball, tentacle of giant octopus or "
            "giant squid, undead eyeball, fish tail, chalks and inks infused "
            "with precious gems, snaketongue, snaketongue, undead eyeball, "
            "adamantine, bone, undead eyeball, fish tail, earth, honeycomb, "
            "mistletoe sprig, undead eyeball, adamantine, bone, undead eyeball,"
            " spider, ash, snaketongue, undead eyeball, adamantine, bone, "
            "undead eyeball, adamantine, silk square, gold-inlaid vial, "
            "polished marble stone, humanoid blood, undead eyeball, adamantine,"
            " bone, undead eyeball, rotten egg, focus, polished marble stone, "
            "fur of bat, mistletoe sprig, silver rod, an item distasteful to "
            "the target, snaketongue, mistletoe sprig, pearl, gold-inlaid vial,"
            " polished marble stone, fur of bat, undead eyeball, kernels of "
            "grain, ammunition, bone, bone, bone, dust, kernels of grain, tiny "
            "piece of target matter, spider, undead eyeball, undead eyeball, "
            "soil mixture in a small bag, quiver, butter, moonseeds, "
            "phosphorus, niter, focus, polished marble stone, fur of bat, "
            "mistletoe sprig, silver rod, an item distasteful to the target, "
            "snaketongue, mistletoe sprig, pearl, gold-inlaid vial, polished "
            "marble stone, undead eyeball, kernels of grain, ammunition, bone, "
            "undead eyeball, kernels of grain, flesh, bone, bone, focus, "
            "kernels of grain, iron filings or powder, fish tail, undead "
            "eyeball, undead eyeball, jade dust, focus, polished marble stone, "
            "fur of bat, mistletoe sprig, silver rod, an item distasteful to "
            "the target, snaketongue, mistletoe sprig, pearl, gold-inlaid vial,"
            " polished marble stone, undead eyeball, kernels of grain, flesh, "
            "bone, undead eyeball, ice, undead eyeball, ice, crystal bead, gum "
            "arabic, snaketongue, gold-inlaid vial, humanoid blood, herbs, "
            "undead eyeball, adamantine, bone, undead eyeball, spider, chalks "
            "and inks infused with precious gems, hot pepper, undead eyeball, "
            "adamantine, bone, undead eyeball, spider, chalks and inks infused "
            "with precious gems, pebble, undead eyeball, adamantine, bone, "
            "undead eyeball, spider, chalks and inks infused with precious "
            "gems, stone, undead eyeball, adamantine, bone, undead eyeball, "
            "spider, tallow, phosphorus, undead eyeball, adamantine, bone, "
            "undead eyeball, adamantine, silk square, gold-inlaid vial, "
            "polished marble stone, humanoid blood, undead eyeball, adamantine,"
            " bone, bone, bone, tears, kernels of grain, cloak, spider, undead "
            "eyeball, undead eyeball, food morsel, quiver, butter, moonseeds, "
            "phosphorus, niter, feather of owl, crystal bead, glass sliver, "
            "undead eyeball, kernels of grain, spheres of glass, bone, undead "
            "eyeball, kernels of grain, ruby (as dust), bone, bone, distilled "
            "spirits, kernels of grain, black pearl (as crushed powder), fish "
            "tail, undead eyeball, undead eyeball, fish tail, feather of owl, "
            "crystal bead, glass sliver, undead eyeball, kernels of grain, ruby"
            " (as dust), bone, undead eyeball, fish tail, undead eyeball, "
            "spider, chalks and inks infused with precious gems, hot pepper, "
            "undead eyeball, adamantine, bone, undead eyeball, spider, chalks "
            "and inks infused with precious gems, pebble, undead eyeball, "
            "adamantine, bone, undead eyeball, adamantine, earth, honeycomb, "
            "mistletoe sprig, honeycomb, undead eyeball, kernels of grain, "
            "leather loop, bone, bone, bone, makeup, kernels of grain, gilded "
            "acorn, spider, undead eyeball, undead eyeball, tentacle of giant "
            "octopus or giant squid, quiver, butter, pearl, polished marble "
            "stone, mistletoe sprig, undead eyeball, kernels of grain, leather "
            "loop, bone, undead eyeball, adamantine, bone, bone, tears, kernels"
            " of grain, alum soaked in vinegar, spider, undead eyeball, undead "
            "eyeball, food morsel, quiver, butter, moonseeds, phosphorus, "
            "niter, feather of owl, chalks and inks infused with precious gems,"
            " glass sliver, undead eyeball, kernels of grain, cork, bone, "
            "undead eyeball, kernels of grain, snakeskin glove, bone, bone, "
            "distilled spirits, kernels of grain, cured leather, fish tail, "
            "undead eyeball, undead eyeball, fish tail, feather of owl, chalks "
            "and inks infused with precious gems, glass sliver, undead eyeball,"
            " kernels of grain, snakeskin glove, bone, undead eyeball, fish "
            "tail, undead eyeball, spider, chalks and inks infused with "
            "precious gems, hot pepper, undead eyeball, adamantine, bone, "
            "undead eyeball, spider, chalks and inks infused with precious "
            "gems, pebble, undead eyeball, adamantine, bone, undead eyeball, "
            "adamantine, earth, honeycomb, mistletoe sprig, honeycomb, undead "
            "eyeball, kernels of grain, leather loop, bone, bone, bone, salt, "
            "kernels of grain, eggshells, spider, undead eyeball, undead "
            "eyeball, bitumen (a drop), quiver, butter, moonseeds, phosphorus, "
            "niter, fur, pearl, polished marble stone, sweet oil, undead "
            "eyeball, kernels of grain, silver cage, bone, undead eyeball, "
            "kernels of grain, flame, bone, bone, pitch, kernels of grain, "
            "crystal sphere, fish tail, undead eyeball, undead eyeball, "
            "adamantine, fur, pearl, polished marble stone, sweet oil, undead "
            "eyeball, kernels of grain, flame, bone, undead eyeball, "
            "adamantine, undead eyeball, food morsel, fur, mandrake root, "
            "earth, herbs, moonseeds, pearl, snaketongue, herbs, undead "
            "eyeball, adamantine, bone, undead eyeball, tentacle of giant "
            "octopus or giant squid, fur, mandrake root, feather of owl, herbs,"
            " rose petals, undead eyeball, adamantine, bone, undead eyeball, "
            "food morsel, feather of owl, mandrake root, earth, herbs, "
            "moonseeds, pearl, snaketongue, herbs, undead eyeball, adamantine, "
            "bone, undead eyeball, tentacle of giant octopus or giant squid, "
            "feather of owl, mandrake root, feather of owl, herbs, rose petals,"
            " undead eyeball, adamantine, bone, bone, bone, fleece, kernels of "
            "grain, tarts, undead eyeball, ruby vial, iron, polished marble "
            "stone, undead eyeball, bone, undead eyeball, bone, undead eyeball,"
            " spider, tentacle of giant octopus or giant squid, coal, undead "
            "eyeball, spider, spider, food morsel, spider, ice, bone, undead "
            "eyeball, giant slug bile, undead eyeball, food morsel, undead "
            "eyeball, undead eyeball, spider, spider, bone, undead eyeball, "
            "spider, undead eyeball, undead eyeball, undead eyeball, spider, "
            "spider, adamantine, undead eyeball, spider, bone, undead eyeball, "
            "spider, spider, food morsel, spider, ice, undead eyeball, spider, "
            "bone, undead eyeball, spider, undead eyeball, food morsel, undead "
            "eyeball, adamantine, spider, ice, bone, undead eyeball, spider, "
            "undead eyeball, adamantine, undead eyeball, food morsel, spider, "
            "ice, bone, undead eyeball, spider, undead eyeball, food morsel, "
            "undead eyeball, spider, spider, ice, bone, bone, tentacle of giant"
            " octopus or giant squid, fish tail, undead eyeball, spider, "
            "spider, food morsel, spider, ice, bone, undead eyeball, shamrock, "
            "undead eyeball, ruby vial, undead eyeball, earth, bone, undead "
            "eyeball, spider, undead eyeball, food morsel, fish tail, ice, "
            "bone, bone, fish tail, fish tail, fish tail, adamantine, bone, "
            "undead eyeball, adamantine, undead eyeball, spider, undead "
            "eyeball, spider, bone, undead eyeball, adamantine, undead eyeball,"
            " adamantine, undead eyeball, ice, bone, bone")

potion_2 = ("magnifying glass, kernels of grain, silver spoon, fish tail, "
            "undead eyeball, undead eyeball, coal, ash, silver rod, gold-inlaid"
            " vial, rose petals, silver rod, honeycomb, phosphorus, undead "
            "eyeball, kernels of grain, tarts, bone, undead eyeball, coal, "
            "undead eyeball, tentacle of giant octopus or giant squid, glass "
            "sliver, honeycomb, rose petals, pearl, snaketongue, undead "
            "eyeball, adamantine, bone, undead eyeball, tentacle of giant "
            "octopus or giant squid, focus, polished marble stone, gum arabic, "
            "an item distasteful to the target, mistletoe sprig, undead "
            "eyeball, kernels of grain, reed, bone, undead eyeball, ice, "
            "crystal bead, an item distasteful to the target, mistletoe sprig, "
            "gum arabic, an item distasteful to the target, mistletoe sprig, "
            "undead eyeball, kernels of grain, caterpillar cocoon, bone, undead"
            " eyeball, adamantine, silk square, gum arabic, an item distasteful"
            " to the target, fur of bat, undead eyeball, kernels of grain, "
            "sulfur, bone, undead eyeball, adamantine, feather of owl, crystal "
            "bead, glass sliver, fur of bat, undead eyeball, kernels of grain, "
            "spheres of glass, bone, undead eyeball, adamantine, feather of "
            "owl, chalks and inks infused with precious gems, glass sliver, fur"
            " of bat, undead eyeball, kernels of grain, cork, bone, undead "
            "eyeball, tentacle of giant octopus or giant squid, fur, pearl, "
            "polished marble stone, sweet oil, fur of bat, undead eyeball, "
            "kernels of grain, silver cage, bone, bone, bone, sponge, kernels "
            "of grain, adder's stomach, fish tail, undead eyeball, undead "
            "eyeball, jade dust, focus, polished marble stone, gum arabic, an "
            "item distasteful to the target, mistletoe sprig, earth, herbs, "
            "moonseeds, pearl, snaketongue, herbs, undead eyeball, kernels of "
            "grain, reed, bone, undead eyeball, undead eyeball, undead eyeball,"
            " adamantine, ivory portal (miniature), honeycomb, phosphorus, "
            "herbs, undead eyeball, rotten egg, bone, bone, bone, rope, kernels"
            " of grain, jewel-encrusted dagger, fish tail, undead eyeball, "
            "undead eyeball, rotten egg, crystal bead, an item distasteful to "
            "the target, mistletoe sprig, gum arabic, an item distasteful to "
            "the target, mistletoe sprig, earth, herbs, moonseeds, pearl, "
            "snaketongue, herbs, undead eyeball, kernels of grain, caterpillar "
            "cocoon, bone, undead eyeball, undead eyeball, undead eyeball, "
            "adamantine, ivory portal (miniature), honeycomb, phosphorus, "
            "herbs, undead eyeball, rotten egg, bone, bone, bone, tears, "
            "kernels of grain, clay and water, spider, undead eyeball, undead "
            "eyeball, food morsel, quiver, butter, moonseeds, phosphorus, "
            "niter, silk square, gum arabic, an item distasteful to the target,"
            " undead eyeball, kernels of grain, sulfur, bone, undead eyeball, "
            "kernels of grain, gem as powder, bone, bone, silk square, kernels "
            "of grain, clay pot of grave dirt, fish tail, undead eyeball, "
            "undead eyeball, fish tail, silk square, gum arabic, an item "
            "distasteful to the target, undead eyeball, kernels of grain, gem "
            "as powder, bone, undead eyeball, tentacle of giant octopus or "
            "giant squid, undead eyeball, fish tail, chalks and inks infused "
            "with precious gems, snaketongue, snaketongue, undead eyeball, "
            "adamantine, bone, undead eyeball, fish tail, earth, honeycomb, "
            "mistletoe sprig, undead eyeball, adamantine, bone, undead eyeball,"
            " spider, ash, snaketongue, undead eyeball, adamantine, bone, "
            "undead eyeball, adamantine, silk square, gold-inlaid vial, "
            "polished marble stone, humanoid blood, undead eyeball, adamantine,"
            " bone, undead eyeball, rotten egg, focus, polished marble stone, "
            "fur of bat, mistletoe sprig, silver rod, an item distasteful to "
            "the target, snaketongue, mistletoe sprig, pearl, gold-inlaid vial,"
            " polished marble stone, fur of bat, undead eyeball, kernels of "
            "grain, ammunition, bone, bone, bone, dust, kernels of grain, tiny "
            "piece of target matter, spider, undead eyeball, undead eyeball, "
            "soil mixture in a small bag, quiver, butter, moonseeds, "
            "phosphorus, niter, focus, polished marble stone, fur of bat, "
            "mistletoe sprig, silver rod, an item distasteful to the target, "
            "snaketongue, mistletoe sprig, pearl, gold-inlaid vial, polished "
            "marble stone, undead eyeball, kernels of grain, ammunition, bone, "
            "undead eyeball, kernels of grain, flesh, bone, bone, focus, "
            "kernels of grain, iron filings or powder, fish tail, undead "
            "eyeball, undead eyeball, jade dust, focus, polished marble stone, "
            "fur of bat, mistletoe sprig, silver rod, an item distasteful to "
            "the target, snaketongue, mistletoe sprig, pearl, gold-inlaid vial,"
            " polished marble stone, undead eyeball, kernels of grain, flesh, "
            "bone, undead eyeball, ice, undead eyeball, ice, crystal bead, gum "
            "arabic, snaketongue, gold-inlaid vial, humanoid blood, herbs, "
            "undead eyeball, adamantine, bone, undead eyeball, spider, chalks "
            "and inks infused with precious gems, hot pepper, undead eyeball, "
            "adamantine, bone, undead eyeball, spider, chalks and inks infused "
            "with precious gems, pebble, undead eyeball, adamantine, bone, "
            "undead eyeball, spider, chalks and inks infused with precious "
            "gems, stone, undead eyeball, adamantine, bone, undead eyeball, "
            "spider, tallow, phosphorus, undead eyeball, adamantine, bone, "
            "undead eyeball, adamantine, silk square, gold-inlaid vial, "
            "polished marble stone, humanoid blood, undead eyeball, adamantine,"
            " bone, bone, bone, tears, kernels of grain, cloak, spider, undead "
            "eyeball, undead eyeball, food morsel, quiver, butter, moonseeds, "
            "phosphorus, niter, feather of owl, crystal bead, glass sliver, "
            "undead eyeball, kernels of grain, spheres of glass, bone, undead "
            "eyeball, kernels of grain, ruby (as dust), bone, bone, distilled "
            "spirits, kernels of grain, black pearl (as crushed powder), fish "
            "tail, undead eyeball, undead eyeball, fish tail, feather of owl, "
            "crystal bead, glass sliver, undead eyeball, kernels of grain, ruby"
            " (as dust), bone, undead eyeball, fish tail, undead eyeball, "
            "spider, chalks and inks infused with precious gems, hot pepper, "
            "undead eyeball, adamantine, bone, undead eyeball, spider, chalks "
            "and inks infused with precious gems, pebble, undead eyeball, "
            "adamantine, bone, undead eyeball, adamantine, earth, honeycomb, "
            "mistletoe sprig, honeycomb, undead eyeball, kernels of grain, "
            "leather loop, bone, bone, bone, makeup, kernels of grain, gilded "
            "acorn, spider, undead eyeball, undead eyeball, tentacle of giant "
            "octopus or giant squid, quiver, butter, pearl, polished marble "
            "stone, mistletoe sprig, undead eyeball, kernels of grain, leather "
            "loop, bone, undead eyeball, adamantine, bone, bone, tears, kernels"
            " of grain, alum soaked in vinegar, spider, undead eyeball, undead "
            "eyeball, food morsel, quiver, butter, moonseeds, phosphorus, "
            "niter, feather of owl, chalks and inks infused with precious gems,"
            " glass sliver, undead eyeball, kernels of grain, cork, bone, "
            "undead eyeball, kernels of grain, snakeskin glove, bone, bone, "
            "distilled spirits, kernels of grain, cured leather, fish tail, "
            "undead eyeball, undead eyeball, fish tail, feather of owl, chalks "
            "and inks infused with precious gems, glass sliver, undead eyeball,"
            " kernels of grain, snakeskin glove, bone, undead eyeball, fish "
            "tail, undead eyeball, spider, chalks and inks infused with "
            "precious gems, hot pepper, undead eyeball, adamantine, bone, "
            "undead eyeball, spider, chalks and inks infused with precious "
            "gems, pebble, undead eyeball, adamantine, bone, undead eyeball, "
            "adamantine, earth, honeycomb, mistletoe sprig, honeycomb, undead "
            "eyeball, kernels of grain, leather loop, bone, bone, bone, salt, "
            "kernels of grain, eggshells, spider, undead eyeball, undead "
            "eyeball, bitumen (a drop), quiver, butter, moonseeds, phosphorus, "
            "niter, fur, pearl, polished marble stone, sweet oil, undead "
            "eyeball, kernels of grain, silver cage, bone, undead eyeball, "
            "kernels of grain, flame, bone, bone, pitch, kernels of grain, "
            "crystal sphere, fish tail, undead eyeball, undead eyeball, "
            "adamantine, fur, pearl, polished marble stone, sweet oil, undead "
            "eyeball, kernels of grain, flame, bone, undead eyeball, "
            "adamantine, undead eyeball, food morsel, fur, mandrake root, "
            "earth, herbs, moonseeds, pearl, snaketongue, herbs, undead "
            "eyeball, adamantine, bone, undead eyeball, tentacle of giant "
            "octopus or giant squid, fur, mandrake root, feather of owl, herbs,"
            " rose petals, undead eyeball, adamantine, bone, undead eyeball, "
            "food morsel, feather of owl, mandrake root, earth, herbs, "
            "moonseeds, pearl, snaketongue, herbs, undead eyeball, adamantine, "
            "bone, undead eyeball, tentacle of giant octopus or giant squid, "
            "feather of owl, mandrake root, feather of owl, herbs, rose petals,"
            " undead eyeball, adamantine, bone, bone, bone, ruby vial, "
            "adamantine, hen's heart, kernels of grain, tarts, undead eyeball, "
            "ruby vial, iron, polished marble stone, undead eyeball, bone, "
            "undead eyeball, bone, undead eyeball, ice, tentacle of giant "
            "octopus or giant squid, coal, undead eyeball, spider, spider, food"
            " morsel, spider, ice, bone, undead eyeball, giant slug bile, "
            "undead eyeball, food morsel, undead eyeball, undead eyeball, "
            "spider, spider, bone, undead eyeball, spider, undead eyeball, "
            "undead eyeball, undead eyeball, spider, spider, adamantine, undead"
            " eyeball, spider, bone, undead eyeball, spider, spider, food "
            "morsel, spider, ice, undead eyeball, spider, bone, undead eyeball,"
            " spider, undead eyeball, food morsel, undead eyeball, adamantine, "
            "spider, ice, bone, undead eyeball, spider, undead eyeball, "
            "adamantine, undead eyeball, food morsel, spider, ice, bone, undead"
            " eyeball, spider, undead eyeball, food morsel, undead eyeball, "
            "spider, spider, ice, bone, bone, tentacle of giant octopus or "
            "giant squid, soil mixture in a small bag, undead eyeball, spider, "
            "spider, food morsel, spider, ice, bone, undead eyeball, spider, "
            "undead eyeball, food morsel, undead eyeball, spider, spider, ice, "
            "bone, undead eyeball, spider, undead eyeball, spider, undead "
            "eyeball, food morsel, spider, ice, bone, undead eyeball, spider, "
            "undead eyeball, food morsel, undead eyeball, adamantine, spider, "
            "ice, bone, undead eyeball, spider, undead eyeball, adamantine, "
            "undead eyeball, food morsel, spider, ice, bone, undead eyeball, "
            "spider, undead eyeball, food morsel, undead eyeball, spider, "
            "spider, ice, bone, undead eyeball, spider, undead eyeball, spider,"
            " undead eyeball, giant slug bile, spider, ice, bone, undead "
            "eyeball, spider, undead eyeball, ruby vial, undead eyeball, bone, "
            "undead eyeball, food morsel, spider, adamantine, bone, undead "
            "eyeball, quartz, undead eyeball, giant slug bile, fish tail, "
            "spider, bone, undead eyeball, giant slug bile, undead eyeball, "
            "food morsel, undead eyeball, ruby vial, undead eyeball, bone, "
            "spider, spider, bone, undead eyeball, spider, undead eyeball, "
            "giant slug bile, undead eyeball, food morsel, spider, ice, undead "
            "eyeball, spider, bone, undead eyeball, shamrock, undead eyeball, "
            "kernels of grain, reed, adamantine, spider, bone, undead eyeball, "
            "spider, undead eyeball, giant slug bile, undead eyeball, food "
            "morsel, spider, ice, undead eyeball, undead eyeball, bone, undead "
            "eyeball, silver mirror, undead eyeball, ruby vial, giant slug "
            "bile, silver rod, bone, undead eyeball, quartz, undead eyeball, "
            "ruby vial, undead eyeball, ruby vial, bone, undead eyeball, "
            "spider, undead eyeball, food morsel, fish tail, ice, bone, bone, "
            "tentacle of giant octopus or giant squid, ice, undead eyeball, "
            "spider, spider, food morsel, spider, ice, bone, undead eyeball, "
            "rotten egg, undead eyeball, food morsel, undead eyeball, kernels "
            "of grain, mica chip, spider, spider, bone, undead eyeball, spider,"
            " undead eyeball, food morsel, undead eyeball, ice, spider, ice, "
            "undead eyeball, spider, bone, undead eyeball, spider, undead "
            "eyeball, ice, fish tail, ice, undead eyeball, spider, bone, undead"
            " eyeball, spider, undead eyeball, food morsel, undead eyeball, "
            "spider, spider, ice, undead eyeball, undead eyeball, bone, undead "
            "eyeball, spider, undead eyeball, adamantine, fish tail, ice, "
            "undead eyeball, undead eyeball, bone, bone, tentacle of giant "
            "octopus or giant squid, coal, undead eyeball, spider, spider, food"
            " morsel, spider, ice, bone, undead eyeball, rotten egg, undead "
            "eyeball, food morsel, undead eyeball, ruby vial, undead eyeball, "
            "sulfur, spider, spider, bone, undead eyeball, spider, undead "
            "eyeball, food morsel, undead eyeball, ice, spider, ice, undead "
            "eyeball, spider, bone, undead eyeball, spider, undead eyeball, "
            "ice, fish tail, ice, undead eyeball, spider, bone, undead eyeball,"
            " talcum powder, undead eyeball, kernels of grain, club, "
            "adamantine, undead eyeball, bone, undead eyeball, spider, undead "
            "eyeball, food morsel, undead eyeball, spider, spider, ice, undead "
            "eyeball, undead eyeball, bone, undead eyeball, spider, undead "
            "eyeball, adamantine, fish tail, ice, undead eyeball, undead "
            "eyeball, bone, bone, tentacle of giant octopus or giant squid, "
            "adamantine, undead eyeball, spider, spider, food morsel, spider, "
            "ice, bone, undead eyeball, talcum powder, undead eyeball, ruby "
            "vial, undead eyeball, ruby (as dust), bone, undead eyeball, "
            "spider, undead eyeball, food morsel, undead eyeball, spider, "
            "spider, ice, bone, undead eyeball, spider, undead eyeball, "
            "adamantine, fish tail, ice, bone, bone, tentacle of giant octopus "
            "or giant squid, bitumen (a drop), undead eyeball, spider, undead "
            "eyeball, spider, undead eyeball, food morsel, spider, ice, bone, "
            "undead eyeball, quartz, undead eyeball, spider, bone, undead "
            "eyeball, giant slug bile, undead eyeball, food morsel, undead "
            "eyeball, spider, spider, spider, bone, undead eyeball, spider, "
            "spider, giant slug bile, spider, ice, bone, undead eyeball, "
            "spider, undead eyeball, adamantine, undead eyeball, food morsel, "
            "spider, ice, bone, undead eyeball, silver mirror, undead eyeball, "
            "ruby vial, giant slug bile, silver rod, adamantine, spider, bone, "
            "undead eyeball, quartz, undead eyeball, ruby vial, undead eyeball,"
            " ruby vial, adamantine, spider, bone, undead eyeball, shamrock, "
            "undead eyeball, giant slug bile, fish tail, spider, bone, undead "
            "eyeball, spider, undead eyeball, food morsel, fish tail, ice, "
            "bone, bone, undead eyeball, adamantine, fish tail, humanoid blood,"
            " kernels of grain, nut shells, ruby vial, undead eyeball, food "
            "morsel, rotten egg, kernels of grain, flesh, ruby vial, undead "
            "eyeball, ointment for the eyes, ruby vial, undead eyeball, "
            "snakeskin glove, ruby vial, undead eyeball, eyelash in gum arabic,"
            " ruby vial, undead eyeball, honey drop, kernels of grain, glass or"
            " crystal bead, ruby vial, undead eyeball, melee weapon, ruby vial,"
            " undead eyeball, fur, fleece, kernels of grain, sesame seeds, "
            "kernels of grain, tarts, soil mixture in a small bag, ruby vial, "
            "undead eyeball, feather of hummingbird, string, earth, tallow, "
            "ruby vial, undead eyeball, spider, pitch, ruby vial, undead "
            "eyeball, knotted string, bone, ruby vial, undead eyeball, pitch, "
            "feldspar, ruby vial, undead eyeball, wisp of smoke, kernels of "
            "grain, holy symbol, food morsel, ruby vial, undead eyeball, "
            "licorice root shaving, ruby vial, undead eyeball, sapphire, hot "
            "pepper, fur of bloodhound, ruby vial, undead eyeball, crystal or "
            "glass cone, bone dust, kernels of grain, reliquary containing a "
            "sacred relic, magic item, ruby vial, undead eyeball, silver cage, "
            "kernels of grain, reed, kernels of grain, air, granite, ruby vial,"
            " undead eyeball, caterpillar cocoon, polished marble stone, ruby "
            "vial, undead eyeball, spheres of glass, ruby vial, undead eyeball,"
            " bone dust, kernels of grain, club, humanoid blood, ruby vial, "
            "undead eyeball, paper or leaf funnel, ruby vial, undead eyeball, "
            "lead, ruby vial, undead eyeball, sesame seeds, ruby vial, undead "
            "eyeball, sponge, kernels of grain, silver rings, ink lead-based, "
            "ruby vial, undead eyeball, thorns, artistic representation of "
            "caster, ruby vial, undead eyeball, fan, ruby vial, undead eyeball,"
            " mercury, ruby vial, undead eyeball, cloth wad, kernels of grain, "
            "thorns, kernels of grain, black onyx stone, ruby vial, undead "
            "eyeball, reliquary containing a sacred relic, kernels of grain, "
            "yew leaf, ruby vial, undead eyeball, twig from a tree that has "
            "been struck by lightning, kernels of grain, holy/unholy water, "
            "kernels of grain, eggshell, kernels of grain, silver cage, "
            "diamond, ruby vial, undead eyeball, ice, kernels of grain, "
            "snakeskin glove, ruby vial, undead eyeball, leather loop, ruby "
            "vial, undead eyeball, adamantine, kernels of grain, wood, ointment"
            " for the eyes, kernels of grain, green plant, jade circlet, ruby "
            "vial, undead eyeball, holy symbol, lime, ruby vial, undead "
            "eyeball, cork, ruby vial, undead eyeball, polished marble stone, "
            "ruby vial, undead eyeball, glass or crystal bead, ruby vial, "
            "undead eyeball, sulfur, ruby vial, undead eyeball, talcum powder, "
            "quartz, kernels of grain, gem or other ornamental container, "
            "miniature hand sculpted from clay, kernels of grain, flame, stone,"
            " obsidian, marked sticks or bones, kernels of grain, gem, kernels "
            "of grain, caterpillar cocoon, mistletoe, ruby vial, undead "
            "eyeball, flame, ruby vial, undead eyeball, rotten egg, ruby vial, "
            "undead eyeball, mistletoe, kernels of grain, gem as powder, ruby "
            "vial, undead eyeball, shamrock, ruby vial, undead eyeball, silver "
            "whistle, parchment with holy word written upon it, ruby vial, "
            "undead eyeball, hot pepper, forked twig, bone, fish tail, humanoid"
            " blood, ruby vial, undead eyeball, silver rod, ruby vial, undead "
            "eyeball, brimstone, ruby vial, undead eyeball, ivory portal "
            "(miniature), mandrake root, brimstone, rock chip, ruby vial, "
            "undead eyeball, agate, mistletoe sprig, ruby vial, undead eyeball,"
            " black onyx stone, ruby vial, undead eyeball, umber hulk blood, "
            "ruby vial, undead eyeball, gem, kernels of grain, copper piece, "
            "kernels of grain, clay pot of brackish water, ruby vial, undead "
            "eyeball, forked metal rod, ruby vial, undead eyeball, feldspar, "
            "salt, kernels of grain, ruby (as dust), ruby vial, undead eyeball,"
            " bone, kernels of grain, legume seed, ruby vial, undead eyeball, "
            "nut shells, ruby vial, undead eyeball, fleece, ruby vial, undead "
            "eyeball, clay model of a ziggurat, kernels of grain, sulfur, "
            "kernels of grain, exquisite chest, ruby vial, undead eyeball, "
            "holy/unholy water, ruby vial, undead eyeball, marked sticks or "
            "bones, licorice root shaving, ruby vial, undead eyeball, guano, "
            "ruby vial, undead eyeball, copper piece, kernels of grain, leather"
            " loop, ruby vial, undead eyeball, skunk cabbage leaves, sponge, "
            "kernels of grain, ruby vial, ruby vial, undead eyeball, spiderweb,"
            " ivory portal (miniature), ruby vial, undead eyeball, yew leaf, "
            "ruby vial, undead eyeball, flesh, ruby vial, undead eyeball, "
            "humanoid blood, kernels of grain, mica chip, ruby vial, undead "
            "eyeball, holly berry, ash, twig from a tree that has been struck "
            "by lightning, ruby vial, undead eyeball, string, kernels of grain,"
            " knotted string, ruby vial, undead eyeball, copper pieces, ruby "
            "vial, undead eyeball, thread, ruby vial, undead eyeball, ash, "
            "kernels of grain, umber hulk blood, eyeball, ruby vial, undead "
            "eyeball, green plant, ruby vial, undead eyeball, incense, ruby "
            "vial, undead eyeball, jade circlet, ruby vial, undead eyeball, "
            "eyeball, kernels of grain, grasshopper's hind leg, ruby vial, "
            "undead eyeball, gum arabic, silver rod, ruby vial, undead eyeball,"
            " club, ruby vial, undead eyeball, giant slug bile, ruby vial, "
            "undead eyeball, feather of owl, ruby vial, undead eyeball, silver "
            "rings, iron, adamantine, kernels of grain, forked metal rod, "
            "incense, ruby vial, undead eyeball, wood, kernels of grain, silver"
            " pins, ruby vial, undead eyeball, ruby vial, kernels of grain, "
            "fan, ruby vial, undead eyeball, diamond, kernels of grain, skunk "
            "cabbage leaves, ruby vial, undead eyeball, obsidian, kernels of "
            "grain, ammunition, niter, ruby vial, undead eyeball, reed, kernels"
            " of grain, clay model of a ziggurat, kernels of grain, crystal or "
            "glass cone, ruby vial, undead eyeball, stone, ruby vial, undead "
            "eyeball, copper wire, ruby vial, undead eyeball, mandrake root, "
            "ruby vial, undead eyeball, lime, ruby vial, undead eyeball, magic "
            "item, ruby vial, undead eyeball, oil, kernels of grain, guano, "
            "ruby vial, undead eyeball, glowworm, ruby vial, undead eyeball, "
            "earth, ruby vial, undead eyeball, quartz, kernels of grain, honey "
            "drop, ruby vial, undead eyeball, salt, kernels of grain, silver "
            "whistle, ruby vial, undead eyeball, rock chip, kernels of grain, "
            "flea (living), ruby vial, undead eyeball, exquisite chest, lead, "
            "ruby vial, undead eyeball, glass eye, ruby vial, undead eyeball, "
            "mica chip, ruby vial, undead eyeball, tallow, ruby vial, undead "
            "eyeball, silver mirror, kernels of grain, feather of hummingbird, "
            "ruby vial, undead eyeball, clay pot of brackish water, gilded "
            "skull, bone, fish tail, jade circlet, ruby vial, undead eyeball, "
            "hand mirror, ruby vial, undead eyeball, gem or other ornamental "
            "container, spider, kernels of grain, copper pieces, ruby vial, "
            "undead eyeball, parchment with holy word written upon it, ruby "
            "vial, undead eyeball, granite, kernels of grain, eyelash in gum "
            "arabic, kernels of grain, copper wire, kernels of grain, hand "
            "mirror, ruby vial, undead eyeball, fur of bloodhound, blood, ruby "
            "vial, undead eyeball, flea (living), wisp of smoke, ruby vial, "
            "undead eyeball, iron, mercury, cloth wad, ruby vial, undead "
            "eyeball, gem as powder, ruby vial, undead eyeball, soil mixture in"
            " a small bag, ruby vial, undead eyeball, ink lead-based, ruby "
            "vial, undead eyeball, air, silver mirror, kernels of grain, "
            "thread, ruby vial, undead eyeball, legume seed, kernels of grain, "
            "glass eye, ice, ruby vial, undead eyeball, tarts, ruby vial, "
            "undead eyeball, miniature hand sculpted from clay, gum arabic, "
            "giant slug bile, kernels of grain, glowworm, kernels of grain, "
            "agate, kernels of grain, spheres of glass, shamrock, ruby vial, "
            "undead eyeball, grasshopper's hind leg, kernels of grain, paper or"
            " leaf funnel, ruby vial, undead eyeball, forked twig, feather of "
            "owl, kernels of grain, sapphire, kernels of grain, melee weapon, "
            "ruby vial, undead eyeball, blood, ruby vial, undead eyeball, "
            "silver pins, talcum powder, spiderweb, ruby vial, undead eyeball, "
            "gilded skull, ruby vial, undead eyeball, moonseeds, ruby vial, "
            "undead eyeball, mistletoe sprig, ruby vial, undead eyeball, "
            "artistic representation of caster, moonseeds, fur, ruby vial, "
            "undead eyeball, eggshell, kernels of grain, oil, kernels of grain,"
            " holly berry, ruby vial, undead eyeball, ruby (as dust), kernels "
            "of grain, cork, ruby vial, undead eyeball, niter, ruby vial, "
            "undead eyeball, ammunition, bone, fish tail, salt, kernels of "
            "grain, crystal or glass cone, spiderweb, spiderweb, kernels of "
            "grain, grasshopper's hind leg, kernels of grain, flea (living), "
            "kernels of grain, skunk cabbage leaves, kernels of grain, "
            "grasshopper's hind leg, kernels of grain, eyelash in gum arabic, "
            "kernels of grain, glowworm, kernels of grain, flea (living), "
            "spiderweb, kernels of grain, reliquary containing a sacred relic, "
            "kernels of grain, honey drop, kernels of grain, grasshopper's hind"
            " leg, kernels of grain, eyelash in gum arabic, gilded skull, "
            "kernels of grain, fan, string, kernels of grain, grasshopper's "
            "hind leg, kernels of grain, agate, gilded skull, kernels of grain,"
            " wood, kernels of grain, club, kernels of grain, honey drop, bone,"
            " spider, soil mixture in a small bag, fish tail, adamantine, bone,"
            " undead eyeball, adamantine, undead eyeball, spider, undead "
            "eyeball, spider, bone, undead eyeball, adamantine, undead eyeball,"
            " adamantine, undead eyeball, ice, bone, undead eyeball, ice, "
            "undead eyeball, spider, undead eyeball, food morsel, bone, undead "
            "eyeball, ice, undead eyeball, spider, undead eyeball, food morsel,"
            " bone, undead eyeball, ice, undead eyeball, adamantine, undead "
            "eyeball, artistic representation of caster, bone, undead eyeball, "
            "food morsel, undead eyeball, spider, undead eyeball, soil mixture "
            "in a small bag, bone, undead eyeball, food morsel, undead eyeball,"
            " adamantine, undead eyeball, soil mixture in a small bag, undead "
            "eyeball, spider, bone, undead eyeball, food morsel, undead "
            "eyeball, ice, undead eyeball, giant slug bile, bone, undead "
            "eyeball, giant slug bile, undead eyeball, spider, undead eyeball, "
            "magic item, bone, undead eyeball, giant slug bile, undead eyeball,"
            " adamantine, undead eyeball, magic item, undead eyeball, spider, "
            "bone, undead eyeball, giant slug bile, undead eyeball, ice, undead"
            " eyeball, rotten egg, bone, undead eyeball, rotten egg, undead "
            "eyeball, spider, undead eyeball, talcum powder, bone, undead "
            "eyeball, rotten egg, undead eyeball, adamantine, undead eyeball, "
            "talcum powder, undead eyeball, spider, bone, undead eyeball, "
            "artistic representation of caster, undead eyeball, spider, undead "
            "eyeball, licorice root shaving, bone, undead eyeball, artistic "
            "representation of caster, undead eyeball, adamantine, undead "
            "eyeball, licorice root shaving, undead eyeball, spider, bone, bone")

descr_1 = (
    'frightening, virtual, danish, flimsy, gruesome great, dark '
    'oppressive, bad, average, virtual, last, more strange, inhospitable, '
    'slimy, average, few dismal')

descr_2 = (
    'flimsy, gruesome great, dark oppressive, bad, average, virtual, '
    'last, more strange, inhospitable, slimy, average, few dismal, '
    'flimsy, dark and gruesome, inhospitable, inhospitable, frightening, '
    'last, slimy, nicest, solid, dark oppressive, few dismal, deep '
    'subterranean, last, gruesome great, average, gruesome great, '
    'average, cruel, damned, common, bad')


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
  print('[+] Wizardcult dump tables script started.')

  vm_prog_1 = [wizardcult_tables_Ingredients.index(p) for p in potion_1.split(', ')]
  vm_prog_2 = [wizardcult_tables_Ingredients.index(p) for p in potion_2.split(', ')]

  open('prog_1.vm', 'wb').write(bytes(vm_prog_1))
  open('prog_2.vm', 'wb').write(bytes(vm_prog_2))
  print(f'[+] VM program #1: {len(vm_prog_1)} bytes. Saved as `prog_1.vm`')
  print(f'[+] VM program #2: {len(vm_prog_2)} bytes. Saved as `prog_2.vm`')

  cmd_1 = [wizardcult_tables_DungeonDescriptions.index(d) for d in descr_1.split(', ')]
  cmd_2 = [wizardcult_tables_DungeonDescriptions.index(d) for d in descr_2.split(', ')]

  print('[+] VM #1 command input:', ''.join('%c' % c for c in cmd_1))
  print('[+] VM #2 command input:', ''.join('%c' % c for c in cmd_2))


# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop:~/ctf/flare-on-2021/10_wizardcult$ ./wizardcult_convert.py 
[+] Wizardcult dump tables script started.
[+] VM program #1: 730 bytes. Saved as `prog_1.vm`
[+] VM program #2: 1819 bytes. Saved as `prog_2.vm`
[+] VM #1 command input: ls /mages_tower
[+] VM #2 command input: /mages_tower/cool_wizard_meme.png
'''
# ----------------------------------------------------------------------------------------
