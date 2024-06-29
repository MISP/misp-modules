function getTextColor(hex) {
    hex = hex.slice(1);
    var r = parseInt(hex.substring(0,2), 16);
    var g = parseInt(hex.substring(2,4), 16);
    var b = parseInt(hex.substring(4,6), 16);
    var avg = ((2 * r) + b + (3 * g))/6;
    if (avg < 128) {
        return 'white';
    } else {
        return 'black';
    }
}

function mapIcon(iconName) {
    switch (iconName) {
        case 'android':
            return '<i class="fab fa-android"></i>';
        case 'battery-full':
            return '<i class="fas fa-battery-full"></i>';
        case 'btc':
            return '<i class="fab fa-btc"></i>';
        case 'bug':
            return '<i class="fas fa-bug"></i>';
        case 'bullseye':
            return '<i class="fas fa-bullseye"></i>';
        case 'cart-arrow-down':
            return '<i class="fas fa-cart-arrow-down"></i>';
        case 'certificate':
            return '<i class="fas fa-certificate"></i>';
        case 'chess-pawn':
            return '<i class="fas fa-chess-pawn"></i>';
        case 'cloud':
            return '<i class="fas fa-cloud"></i>';
        case 'database':
            return '<i class="fas fa-database"></i>';
        case 'dollar-sign':
            return '<i class="fas fa-dollar-sign"></i>';
        case 'door-open':
            return '<i class="fas fa-door-open"></i>';
        case 'eye':
            return '<i class="fas fa-eye"></i>';
        case 'file-code':
            return '<i class="fas fa-file-code"></i>';
        case 'fire':
            return '<i class="fas fa-fire"></i>';
        case 'gavel':
            return '<i class="fas fa-gavel"></i>';
        case 'globe':
            return '<i class="fas fa-globe"></i>';
        case 'globe-europe':
            return '<i class="fas fa-globe-europe"></i>';
        case 'industry':
            return '<i class="fas fa-industry"></i>';
        case 'internet-explorer':
            return '<i class="fab fa-internet-explorer"></i>';
        case 'key':
            return '<i class="fas fa-key"></i>';
        case 'layer-group':
            return '<i class="fas fa-layer-group"></i>';
        case 'link':
            return '<i class="fas fa-link"></i>';
        case 'map':
            return '<i class="fas fa-map"></i>';
        case 'mobile':
            return '<i class="fas fa-mobile"></i>';
        case 'optin-monster':
            return '<i class="fab fa-optin-monster"></i>';
        case 'plane':
            return '<i class="fas fa-plane"></i>';
        case 'shield-alt':
            return '<i class="fas fa-shield-alt"></i>';
        case 'shield-virus':
            return '<i class="fas fa-shield-virus"></i>';
        case 'sitemap':
            return '<i class="fas fa-sitemap"></i>';
        case 'skull-crossbones':
            return '<i class="fas fa-skull-crossbones"></i>';
        case 'user-ninja':
            return '<i class="fas fa-user-ninja"></i>';
        case 'user-secret':
            return '<i class="fas fa-user-secret"></i>';
        case 'user-shield':
            return '<i class="fas fa-user-shield"></i>';
        case 'wheelchair':
            return '<i class="fas fa-wheelchair"></i>';
    }
}
