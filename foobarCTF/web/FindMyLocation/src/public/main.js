mapboxgl.accessToken =
    "pk.eyJ1IjoiYWVsZWN0cm9uIiwiYSI6ImNrenFrMnB6MjU4aHozMG8xd2NyOW1wMXIifQ.pxgiSakfpfYjvjLXlFyFvA"

navigator.geolocation.getCurrentPosition(successLocation, errorLocation, {
    enableHighAccuracy: true
})

function successLocation(position) {
    setupMap([position.coords.longitude, position.coords.latitude])
}

function errorLocation() {
    setupMap([-2.24, 53.48])
}

let lists;
function test(list) {
    lists(list)
}

function setupMap(center) {
    const map = new mapboxgl.Map({
        container: "map",
        style: "mapbox://styles/mapbox/streets-v11",
        center: center,
        zoom: 4
    })


    lists = (data) => {
        console.log(data, "line 76")

        const geojson = {
            'type': 'FeatureCollection',
            'features': [
                {
                    'type': 'Feature',
                    'geometry': {
                        'type': 'Point',
                        'coordinates': [data.features[0].center[0],data.features[0].center[1]]
                    },
                    'properties': {
                        'title': 'User',
                        'description': `${data.features[0].place_name}`
                    }
                }
            ]
        };


        // add markers to map
        for (const feature of geojson.features) {
            // create a HTML element for each feature
            const el = document.createElement('div');
            el.className = 'marker';

            // make a marker for each feature and add it to the map
            new mapboxgl.Marker(el)
                .setLngLat(feature.geometry.coordinates)
                .setPopup(
                    new mapboxgl.Popup({ offset: 25 }) // add popups
                        .setHTML(
                            `<h3>${feature.properties.title}</h3><p>${feature.properties.description}</p>`
                        )
                )
                .addTo(map);
        }
    }




    // let geojson;
    async function showPosition(position) {



        const res = await fetch(`https://api.mapbox.com/geocoding/v5/mapbox.places/${position.coords.longitude},${position.coords.latitude}.json?access_token=pk.eyJ1IjoiYWVsZWN0cm9uIiwiYSI6ImNrenFrMnB6MjU4aHozMG8xd2NyOW1wMXIifQ.pxgiSakfpfYjvjLXlFyFvA`)
        const result = await res.json()
        console.log(result.features[2].place_name)

        const geojson = {
            'type': 'FeatureCollection',
            'features': [
                {
                    'type': 'Feature',
                    'geometry': {
                        'type': 'Point',
                        'coordinates': [position.coords.longitude, position.coords.latitude]
                    },
                    'properties': {
                        'title': 'User',
                        'description': `${result.features[2].place_name}`
                    }
                }
            ]
        };


        // add markers to map
        for (const feature of geojson.features) {
            // create a HTML element for each feature
            const el = document.createElement('div');
            el.className = 'marker';

            // make a marker for each feature and add it to the map
            new mapboxgl.Marker(el)
                .setLngLat(feature.geometry.coordinates)
                .setPopup(
                    new mapboxgl.Popup({ offset: 25 }) // add popups
                        .setHTML(
                            `<h3>${feature.properties.title}</h3><p>${feature.properties.description}</p>`
                        )
                )
                .addTo(map);
        }

    }



    // for own loaction
    function getLocation() {
        if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition(showPosition);
        } else {
            console.log("Geolocation is not supported by this browser.")
        }
    }

    getLocation()



    const nav = new mapboxgl.NavigationControl()
    map.addControl(nav)

    // var directions = new MapboxDirections({
    //   accessToken: mapboxgl.accessToken
    // })

    //   map.addControl(directions, "top-left")
}