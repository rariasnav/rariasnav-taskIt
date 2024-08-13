export 	const getData = async (fluxFunction, setData) => {
    const response = await fluxFunction();
    if (response) {
        setData(response);
    } 
}