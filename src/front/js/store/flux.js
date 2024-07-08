const getState = ({ getStore, getActions, setStore }) => {
	const baseURL = process.env.BACKEND_URL + "/api";
	const TOKEN = localStorage.getItem('token');

	const createRequestOptions = (method, body = null, isAuthRequired = false) => {
		const headers = {'Content-Type': 'application/json'};
		if (isAuthRequired) {
			headers['Authorization'] = `Bearer ${localStorage.getItem('token')}`;
		}
		return {
			method,
			headers,
			body: body ? JSON.stringify(body) : null
		};
	}
	const handleResponse = async (response) => {
        if (!response.ok) throw new Error('Network response was not ok');
        return await response.json();
    };
	return {
		store: {
			message: null,
			demo: [
				{
					title: "FIRST",
					background: "white",
					initial: "white"
				},
				{
					title: "SECOND",
					background: "white",
					initial: "white"
				}
			],
			baseURL: 'https://sturdy-broccoli-69gggxgvv49g2x65x-3001.app.github.dev/api',
			loggedUser: null
		},
		actions: {
			// Use getActions to call a function within a fuction
			exampleFunction: () => {
				getActions().changeColor(0, "green");
			},

			getMessage: async () => {
				try {
					// fetching data from the backend
					const resp = await fetch(process.env.BACKEND_URL + "/api/hello")
					const data = await resp.json()
					setStore({ message: data.message })
					// don't forget to return something, that is how the async resolves
					return data;
				} catch (error) {
					console.log("Error loading message from backend", error)
				}
			},
			changeColor: (index, color) => {
				//get the store
				const store = getStore();

				//we have to loop the entire demo array to look for the respective index
				//and change its color
				const demo = store.demo.map((elm, i) => {
					if (i === index) elm.background = color;
					return elm;
				});

				//reset the global store
				setStore({ demo: demo });
			},
			loadUserDataById: async (id) => {
				try {
					const response = await fetch(`${baseURL}/user/${id}`);
					return await handleResponse(response);
				} catch (error) {
					console.error("Error loading user data", error);
					return false;
				}
			},
			createUser: async (user) => {
				try {
					console.log(user);
					const requestOptions = createRequestOptions('POST', user);
					console.log(requestOptions);
					const response = await fetch(`${baseURL}/signup`, requestOptions);
					console.log(response)
					if (response.ok) return 201;
				} catch (error) {
					console.error("Error creating user", error);
				}
			},
			login: async (email, password) => {
				try {
					const requestOptions = createRequestOptions('POST', { email, password });
					const response = await fetch(`${baseURL}/login`, requestOptions);
					const data = await handleResponse(response);
					if (response.ok) {
						localStorage.setItem("token", data.access_token);
						await getActions().getInMyProfile();
						return true;
					}					
				} catch (error) {
					console.error("Error logging in", error);
				}
				getActions().logout()
				return false
			},
			logout: () => {
				setStore({ loggedUser: false });
				localStorage.removeItem("token");
			},
			getInMyProfile: async () => {
				try {
					const requestOptions = createRequestOptions('GET', null, true);
					const response = await fetch(`${baseURL}/profile`, requestOptions);
					const data = await handleResponse(response);
					if (response.ok) {
						setStore({ loggedUser: data.user });
						return true;
					}
				} catch (error) {
					console.error("Error getting profile information", error);
				}
				getActions().logout();
				return false;
			},
			updateUserInformation: async (user) => {
				try {
					const requestOptions = createRequestOptions('PUT', user, true);
					const response = await fetch(`${baseURL}/user_information`, requestOptions);
					if (response.ok) {
						await getActions().getInMyProfile();
						return 201;
					}
				} catch (error) {
					console.error("Error updating user information", error);
				}
			},
			loadTestData: async () => {
				try {
					const response = await fetch('https://jsonplaceholder.typicode.com/users')
					const data = await response.json()

					if (response.ok) {
						return data
					}
					return false
				} catch (error) {
					return false
				}
			},
			getCategories: async () => {
				try {
					const response = await fetch(`${baseURL}/services_category`);
					return await handleResponse(response);
				} catch (error) {
					console.error("Error getting categories", error);
					return false;
				}
			},
			getSubcategories: async () => {
				try {
					const response = await fetch(`${baseURL}/services_subcategory`);
					return await handleResponse(response);
				} catch (error) {
					console.error("Error getting subcategories", error);
					return false;
				}
			},
			getCategoriesSubcategories: async () => {
				try {
					const response = await fetch(`${baseURL}/services_category_subcategory`)
					return await handleResponse(response);
				} catch (error) {
					console.error("Error getting categoriesSubcategories", error);
					return false;
				}
			},
			postForAService: async (service_request) => {
				const store = getStore();
				const newData = { 
					"email": store.loggedUser.email,
					...service_request
				}
				try {
					const requestOptions = createRequestOptions('POST', newData, true);
					const response = await fetch(`${baseURL}/service_request`, requestOptions)
					if (response.ok) return 201;
				} catch (error) {
					console.error("Error posting service", error);
				}

			},
			getServicesRequests: async () => {
				try {
					const requestOptions = createRequestOptions('GET', null, true);
					const response = await fetch(`${baseURL}/service_request`, requestOptions);
					return await handleResponse(response);
				}
				catch (error) {
					console.error("Error getting service requests", error);
					return false;
				}
			},
			cancelServiceRequest: async (filteredServiceRequestId) => {
				try {
					const requestOptions = createRequestOptions('DELETE', null, true);
					const response = await fetch(`${baseURL}/service_request/${filteredServiceRequestId}`, requestOptions);
					if (response.ok) {
						await getActions().getServicesRequests();
						return 201;
					}
				} catch (error) {
					console.error("Error canceling service request", error);
				}
			},
			offerServiceRequest: async (data, requestServiceOffer) => {
				const store = getStore();
				const newData = {
					"vendor_email": store.loggedUser.email,
					...data,
					...requestServiceOffer
				}
				try {
					const requestOptions = createRequestOptions('POST', newData, true);
					const response = await fetch(`${baseURL}/service_request_offer`, requestOptions);
					if (response.ok) {
						await getActions().getServicesRequests();
						return 201
					}
				} catch (error) {
					console.error("Error offering service request", error);
				}
			},
			getServicesRequestsOffers: async () => {
				try {
					const requestOptions = createRequestOptions('GET', null, true);
					const response = await fetch(`${baseURL}/service_request_offer`, requestOptions)
					return await handleResponse(response);
				} catch (error) {
					console.error("Error getting service request offers", error);
					return false;
				}
			},
			getOfferKnowedle: async () => {
				try {
					const requestOptions = createRequestOptions('GET', null, true);
					const response = await fetch(`${baseURL}/offer_knowledge`, requestOptions)
					return await handleResponse(response);
				} catch (error) {
					console.error("Error getting offer knowledge", error);
					return false;
				}
			},
			updateServicesRequestsOffers: async (index, data) => {
				try {
					const requestOptions = createRequestOptions('PUT', data, true);
					const response = await fetch(`${baseURL}/service_request_offer/${index.service_request_offer_id}/${index.service_request_id}`, requestOptions);
					if (response.ok) {
						await getActions().getServicesRequests();
						await getActions().getServicesRequestsOffers();
						return 201;
					}
				} catch (error) {
					console.error("Error updating services request offer", error);
				}
			},
			updateProfilePicture: async (pictureFile) => {
				try {
					const requestOptions = {
						method: ['PUT'],
						headers: { 'Authorization': `Bearer ${TOKEN}` },						
						body: pictureFile
					};
					const response = await fetch(`${baseURL}/upload_profile_picture`, requestOptions);
					return response.status;
				} catch (error) {
					console.error("Error updating profile picture", error);
					return false;
				}
			},
			uploadGalleryPicture: async (galleryPicture) => {
				try {
					const requestOptions = {
						method: ['POST'],
						headers: { 'Authorization': `Bearer ${TOKEN}` },
						body: galleryPicture
					};
					const response = await fetch(`${baseURL}/user_gallery_pictures`, requestOptions);
					return response.status;
				} catch (error) {
					console.log('Error uploading gallery picture', error);
					return false;
				}
			},
			getGalleryPictures: async () => {
				try {
					const requestOptions = {
						method: ['GET'],
						headers: { 'Authorization': `Bearer ${TOKEN}` }
					}
					const response = await fetch(`${baseURL}/user_gallery_pictures`, requestOptions);
					return await handleResponse(response);
				} catch (error) {
					console.error("Error getting gallery pictures", error);
					return false;
				}
			},
		}
	};
};
export default getState;