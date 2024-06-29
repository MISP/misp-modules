function parseMispObject(misp_object, query_url, functionToCall){

    function generate(misp_object, query_url, functionToCall){
        let $container = $("<div>")
        misp_object.Attribute.forEach(function (v, i) {
            let $query = $("<a>")
            let $query_same = null

            if(v.type != 'counter' && v.type != 'datetime'){
                if(query_url){
                    $query=$("<a>").attr("href", query_url+v.value).text("query").css("margin-left", "10px")
                }
                if(functionToCall){
                    // `_${functionToCall.name}('${v.value}')` refer to 'window._query_as_same = query_as_same' in my vue file
                    $query_same = $("<button>").attr({"onclick": `_${functionToCall.name}('${v.value}')`, 
                                "title": "Query this value with the same attribute and modules as the main query",
                                "class": "btn btn-link"
                                })
                            .text("query as same")
                            .css({"margin-left": "10px", "padding": "0", "--bs-btn-border-width": "0"})
                }
            }
            
            $container.append(
                $("<div>").css("margin-top", "10px").append(
                    $("<h6>").append($("<u>").text(v.object_relation)),
                    $("<div>").css("display", "flex").append(
                        $("<div>").css({
                            "border-left": "2px solid grey",
                            "border-bottom": "2px solid grey",
                            "width": "15px",
                            "height": "15px",
                            "display": "flex",
                            "margin-left": "0.5em",
                        }),
                        $("<div>").text("Type: "+ v.type)
                    ),
                    $("<div>").css("display", "flex").append(
                        $("<div>").css({
                            "border-left": "2px solid grey",
                            "border-bottom": "2px solid grey",
                            "width": "15px",
                            "height": "15px",
                            "display": "flex",
                            "margin-left": "0.5em",
                        }),
                        $("<div>").text("Value: "+ v.value),
                        $query,
                        $query_same
                    )
                )
            )
        });
        return $container
    }

    var $mainContainer = $('<div>')
    let first_elem = $("<div>").css({"display": "flex", "align-items": "baseline"}).append(
        $("<i>").attr({"class": "fa-solid fa-cube", "title": "MISP Object"}),
        $('<h4>').css("margin-left", "5px").append(
            $("<small>").text(misp_object.name)
        )
    )
    $mainContainer.append(first_elem)
    $mainContainer.append(generate(misp_object, query_url, functionToCall))
    $mainContainer.append($("<hr>"))
    return $mainContainer
}

function parseMispAttr(misp_attr, misp_types, key, query_url, query_as_same){
    let $query = $("<a>")
    let $query_same = null

    if(!misp_types.includes('counter') && !misp_types.includes('datetime') ){
        if(query_url){
            $query=$("<a>").attr("href", query_url+misp_attr).text("query").css("margin-left", "10px")
        }
        // `_${functionToCall.name}('${misp_attr}')` refer to 'window._query_as_same = query_as_same' in my vue file
        if(query_as_same){
            $query_same = $("<button>").attr({"onclick": `_${query_as_same.name}('${misp_attr}')`, 
                            "title": "Query this value with the same attribute and modules as the main query",
                            "class": "btn btn-link"
                        })
                    .text("query as same")
                    .css({"margin-left": "10px", "padding": "0", "--bs-btn-border-width": "0"})
        }
    }


    var $mainContainer = $('<div>')
    let cp = key+1
    $mainContainer.append($("<h6>").append($("<u>").text("#Attr "+cp)))
    $mainContainer.append($("<div>").css("display", "flex").append(
        $("<div>").css({
            "border-left": "2px solid grey",
            "border-bottom": "2px solid grey",
            "width": "15px",
            "height": "15px",
            "display": "flex",
            "margin-left": "0.5em",
        }),
        $("<div>").text("Type: "+ misp_types.join(", "))
        )
    )

    $mainContainer.append($("<div>").css("display", "flex").append(
            $("<div>").css({
                "border-left": "2px solid grey",
                "border-bottom": "2px solid grey",
                "width": "15px",
                "height": "15px",
                "display": "flex",
                "margin-left": "0.5em",
            }),
            $("<div>").text("Value: "+ misp_attr),
            $query,
            $query_same
        )
    )

    $mainContainer.append($("<hr>"))
    return $mainContainer
}